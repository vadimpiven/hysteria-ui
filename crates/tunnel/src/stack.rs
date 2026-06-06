//! The smoltcp netstack: a background task that polls the interface, detects new
//! flows from inbound packets, and bridges the TUN to async per-flow streams.
//!
//! A TUN delivers packets for arbitrary destination IPs. smoltcp is a host stack
//! (its sockets bind to specific endpoints), so to forward transparently we set
//! `any_ip` (the interface treats every destination as local) and, on each new
//! TCP SYN, create a socket *listening on that exact destination* — smoltcp then
//! completes the handshake and we hand the flow to the relay.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::Weak;
use std::time::Duration;

use smoltcp::iface::Config as IfaceConfig;
use smoltcp::iface::Interface;
use smoltcp::iface::SocketHandle;
use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::time::Duration as SmolDuration;
use smoltcp::time::Instant;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::IpListenEndpoint;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::TcpPacket;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::device::TunDevice;
use crate::tcp::TcpStream;

/// Per-socket buffer sizes, and the concurrent-flow cap. All bounded for the iOS
/// `NetworkExtension` memory cap; the iOS memory gate tunes them against real RSS
/// (`MAX_FLOWS` × (`TCP_RX_BUFFER` + `TCP_TX_BUFFER`) is the smoltcp ceiling).
const TCP_RX_BUFFER: usize = 16 * 1024;
const TCP_TX_BUFFER: usize = 16 * 1024;
const MAX_FLOWS: usize = 512;
/// Detect dead peers (keep-alive probes) and abort wholly-idle flows so their
/// sockets reach `Closed` and are reaped rather than leaking.
const TCP_KEEP_ALIVE: SmolDuration = SmolDuration::from_secs(15);
const TCP_TIMEOUT: SmolDuration = SmolDuration::from_secs(300);
/// Safety wakeup when smoltcp reports no pending timer.
const IDLE_POLL: Duration = Duration::from_secs(1);

/// A flow's 5-tuple: `(source, destination)`.
type FlowKey = (SocketAddr, SocketAddr);

/// A live TCP flow tracked by the netstack task.
struct Flow {
    key: FlowKey,
    /// `Weak` to the [`TcpStream`]'s liveness token; once it can't upgrade, the
    /// stream has dropped and the socket is safe to remove.
    alive: Weak<()>,
}

/// Live TCP sockets keyed by their smoltcp handle.
type Handles = HashMap<SocketHandle, Flow>;

/// Netstack interface settings supplied by the front-end (matching the TUN).
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// The interface address (must match the TUN's assigned address).
    pub address: Ipv4Addr,
    /// Prefix length of the TUN subnet (on-link reach for app replies).
    pub prefix: u8,
    /// TUN MTU.
    pub mtu: usize,
}

/// State shared between the netstack task and the per-flow async streams. Locked
/// briefly and never across an `.await`.
pub(crate) struct Shared {
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) device: TunDevice,
}

pub(crate) type SharedRef = Arc<Mutex<Shared>>;

/// Lock the shared state, recovering from a poisoned mutex (no panic).
pub(crate) fn lock(shared: &SharedRef) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A proxied TCP flow handed to the relay: the original destination plus the
/// async stream to the local app.
pub(crate) struct TcpFlow {
    pub(crate) dst: SocketAddr,
    pub(crate) stream: TcpStream,
}

/// Start the netstack over `device`. Returns a receiver of accepted TCP flows;
/// the background task runs until `device` errors or the receiver is dropped.
pub(crate) fn start(device: Arc<AsyncDevice>, config: Config) -> mpsc::Receiver<TcpFlow> {
    let mut tun_device = TunDevice::new(config.mtu);
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut tun_device,
        Instant::now(),
    );
    // Accept packets destined to any address, not just our own (transparent
    // forwarding), and place our address on-link so app-bound replies route back.
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddr::V4(config.address).into(),
            config.prefix,
        ));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(config.address);

    let shared: SharedRef = Arc::new(Mutex::new(Shared {
        iface,
        sockets: SocketSet::new(Vec::new()),
        device: tun_device,
    }));
    let notify = Arc::new(Notify::new());
    let (flow_tx, flow_rx) = mpsc::channel::<TcpFlow>(64);

    tokio::spawn(run(device, shared, notify, flow_tx, config.mtu));
    flow_rx
}

/// The netstack task: poll, detect flows, and shuttle packets to/from the TUN.
async fn run(
    device: Arc<AsyncDevice>,
    shared: SharedRef,
    notify: Arc<Notify>,
    flow_tx: mpsc::Sender<TcpFlow>,
    mtu: usize,
) {
    // One TCP socket per live flow; the map dedups SYN retransmits.
    let mut handles: Handles = HashMap::new();
    let mut buf = vec![0u8; mtu.max(1500)];

    loop {
        let poll_delay = {
            let mut guard = lock(&shared);
            // Reborrow the inner struct so field accesses below are disjoint
            // (they are not through the `MutexGuard`'s `Deref`).
            let s = &mut *guard;
            detect_and_accept(s, &mut handles, &notify, &shared, &flow_tx);
            let now = Instant::now();
            s.iface.poll(now, &mut s.device, &mut s.sockets);
            reap_finished(s, &mut handles);
            s.iface.poll_delay(now, &s.sockets)
        };

        // Flush everything smoltcp produced out to the TUN.
        loop {
            let packet = lock(&shared).device.pop_outbound();
            match packet {
                Some(packet) => {
                    if device.send(&packet).await.is_err() {
                        return;
                    }
                },
                None => break,
            }
        }

        // smoltcp's recommended loop: a zero delay means "work is due now", so
        // re-poll immediately rather than arming a `sleep(0)` that hot-loops.
        let timeout = match poll_delay {
            Some(delay) if delay.total_micros() == 0 => continue,
            Some(delay) => Duration::from_micros(delay.total_micros()),
            None => IDLE_POLL,
        };
        tokio::select! {
            read = device.recv(&mut buf) => match read {
                Ok(n) => lock(&shared).device.push_inbound(buf[..n].to_vec()),
                Err(_) => return,
            },
            () = notify.notified() => {},
            () = tokio::time::sleep(timeout) => {},
        }
    }
}

/// If the next inbound packet opens a new TCP flow, create its listening socket
/// and hand the flow to the relay (mirrors Go's `tun.Handler::NewConnection`).
fn detect_and_accept(
    s: &mut Shared,
    handles: &mut Handles,
    notify: &Arc<Notify>,
    shared: &SharedRef,
    flow_tx: &mpsc::Sender<TcpFlow>,
) {
    let Some((src, dst)) = s.device.peek_inbound().and_then(parse_tcp_syn) else {
        return;
    };
    if handles.values().any(|f| f.key == (src, dst)) {
        return; // already tracking this flow (a SYN retransmit)
    }
    if handles.len() >= MAX_FLOWS {
        return; // backlog full: leave the SYN unanswered, like a real listener
    }

    // Reserve a channel slot *before* creating the socket/stream. If the relay
    // backlog is full (or the receiver is gone), we leave the SYN unanswered —
    // like a real listener — without ever constructing, then tearing down, a
    // socket. Tearing one down here would drop the `TcpStream` while we hold the
    // `Shared` lock, and its `Drop` re-locks the same non-reentrant mutex.
    let Ok(permit) = flow_tx.try_reserve() else {
        return;
    };

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]),
    );
    socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
    socket.set_timeout(Some(TCP_TIMEOUT));
    let endpoint = IpListenEndpoint {
        addr: Some(dst.ip().into()),
        port: dst.port(),
    };
    if socket.listen(endpoint).is_err() {
        return;
    }
    let handle = s.sockets.add(socket);

    let alive = Arc::new(());
    let stream = TcpStream::new(
        Arc::clone(shared),
        handle,
        Arc::clone(notify),
        Arc::clone(&alive),
    );
    permit.send(TcpFlow { dst, stream });
    handles.insert(
        handle,
        Flow {
            key: (src, dst),
            alive: Arc::downgrade(&alive),
        },
    );
}

/// Remove sockets whose relay stream has dropped, freeing their buffers. Safe
/// only because a live stream keeps its liveness token, so we never remove a
/// handle a `TcpStream` still references. The stream's `Drop` already queued a
/// FIN via `close()`, which the preceding `poll` flushed.
fn reap_finished(s: &mut Shared, handles: &mut Handles) {
    let finished: Vec<SocketHandle> = handles
        .iter()
        .filter(|(_, flow)| flow.alive.upgrade().is_none())
        .map(|(&handle, _)| handle)
        .collect();
    for handle in finished {
        s.sockets.remove(handle);
        handles.remove(&handle);
    }
}

/// Parse an IPv4 packet; return `(src, dst)` if it is a TCP SYN opening a new
/// connection (SYN set, ACK clear). IPv6 is ignored for now — it needs an
/// interface address and route (the next increment, with UDP).
fn parse_tcp_syn(packet: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    if packet.first()? >> 4 != 4 {
        return None;
    }
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let segment = TcpPacket::new_checked(ip.payload()).ok()?;
    if !segment.syn() || segment.ack() {
        return None;
    }
    Some((
        SocketAddr::new(IpAddr::V4(ip.src_addr()), segment.src_port()),
        SocketAddr::new(IpAddr::V4(ip.dst_addr()), segment.dst_port()),
    ))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;

    use super::*;

    /// Build a minimal IPv4 TCP packet with the given flags for parser tests.
    /// TCP flag bits: SYN = 0x02, ACK = 0x10.
    fn ipv4_tcp(syn: bool, ack: bool) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 20];
        pkt[0] = 0x45; // IPv4, IHL 5 (20-byte header)
        let total = u16::try_from(pkt.len()).unwrap_or(0);
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[9] = 6; // protocol = TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src addr
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]); // dst addr
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port
        pkt[32] = 0x50; // data offset 5 (20-byte TCP header), no options
        pkt[33] = if syn { 0x02 } else { 0 } | if ack { 0x10 } else { 0 };
        pkt
    }

    #[test]
    fn parse_tcp_syn_accepts_a_syn() -> Result<()> {
        let (src, dst) =
            parse_tcp_syn(&ipv4_tcp(true, false)).ok_or_else(|| anyhow!("not a SYN"))?;
        assert_eq!(src, "10.0.0.2:40000".parse()?, "source 5-tuple");
        assert_eq!(dst, "93.184.216.34:443".parse()?, "destination 5-tuple");
        Ok(())
    }

    #[test]
    fn parse_tcp_syn_ignores_non_syn() {
        assert!(
            parse_tcp_syn(&ipv4_tcp(true, true)).is_none(),
            "SYN-ACK ignored"
        );
        assert!(
            parse_tcp_syn(&ipv4_tcp(false, true)).is_none(),
            "ACK ignored"
        );
        assert!(parse_tcp_syn(&[]).is_none(), "empty ignored");
        assert!(parse_tcp_syn(&[0x60]).is_none(), "truncated ignored");
    }
}
