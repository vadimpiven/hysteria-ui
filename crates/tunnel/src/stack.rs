//! The smoltcp netstack: a background task that polls the interface, detects new
//! flows from inbound packets, and bridges the TUN to async per-flow streams.
//!
//! A TUN delivers packets for arbitrary destination IPs. smoltcp is a host stack
//! (its sockets bind to specific endpoints), so to forward transparently we set
//! `any_ip` (the interface treats every destination as local) and, on each new
//! TCP SYN, create a socket *listening on that exact destination* — smoltcp then
//! completes the handshake and we hand the flow to the relay. UDP is handled the
//! same way (a socket bound per destination; see [`crate::udp`]), but the netstack
//! itself stays Hysteria-agnostic: it only trades TCP flows and UDP datagrams over
//! channels, never touching the client.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::Weak;
use std::time::Duration;
use std::time::Instant as StdInstant;

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
use smoltcp::wire::Ipv6ExtHeader;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::TcpPacket;
use smoltcp::wire::UdpPacket;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tun_rs::AsyncDevice;

use crate::device::TunDevice;
use crate::tcp::TcpStream;
use crate::udp::UdpInbound;
use crate::udp::UdpOutbound;
use crate::udp::UdpSockets;

/// Detect dead peers (keep-alive probes) and abort wholly-idle flows so their
/// sockets reach `Closed` and are reaped rather than leaking.
const TCP_KEEP_ALIVE: SmolDuration = SmolDuration::from_secs(15);
const TCP_TIMEOUT: SmolDuration = SmolDuration::from_secs(300);
/// Safety wakeup when smoltcp reports no pending timer.
const IDLE_POLL: Duration = Duration::from_secs(1);
/// Idle UDP destinations are reaped after this long (mirrors the Go TUN handler's
/// 300 s UDP timeout). Activity in *either* direction keeps a flow alive.
pub(crate) const UDP_IDLE: Duration = Duration::from_mins(5);
/// Cap on the IPv6 extension-header chain we walk before giving up (malformed or
/// adversarial chains never trap us in a loop).
const MAX_EXT_HEADERS: usize = 8;
/// Scratch buffer for draining UDP datagrams (max IP payload).
const UDP_SCRATCH: usize = 65_535;

/// Per-socket buffer sizes and concurrency caps, all bounded so the netstack's
/// memory is provisioned, not unbounded. Exposed on [`Config`] so the FFI layer
/// can shrink them to fit a tight host budget (the iOS `NetworkExtension` cap is
/// the binding one, ~15 MiB on older devices) without touching this crate.
///
/// Worst-case smoltcp buffer ceiling with the defaults:
/// `max_tcp_flows × (tcp_rx + tcp_tx)` (512 × 32 KiB = 16 MiB) plus
/// `max_udp_sockets × (udp_rx + udp_tx)` (256 × 48 KiB ≈ 12 MiB) ≈ 28 MiB —
/// above that budget, so the embedder lowers these against real measured RSS.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Max concurrent TCP flows; further SYNs are left unanswered (like a full
    /// listener backlog).
    pub max_tcp_flows: usize,
    pub tcp_rx_buffer: usize,
    pub tcp_tx_buffer: usize,
    /// Max concurrent UDP destinations (one smoltcp socket each).
    pub max_udp_sockets: usize,
    pub udp_rx_buffer: usize,
    pub udp_tx_buffer: usize,
    /// Datagrams each UDP socket can buffer per direction (metadata slots).
    pub udp_packets: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tcp_flows: 512,
            tcp_rx_buffer: 16 * 1024,
            tcp_tx_buffer: 16 * 1024,
            max_udp_sockets: 256,
            udp_rx_buffer: 32 * 1024,
            udp_tx_buffer: 16 * 1024,
            udp_packets: 8,
        }
    }
}

/// A flow's 5-tuple: `(source, destination)`.
type FlowKey = (SocketAddr, SocketAddr);

/// An IP packet parsed down to L4: protocol, source IP, dest IP, and L4 bytes.
type Parsed<'a> = (IpProtocol, IpAddr, IpAddr, &'a [u8]);
/// An L4 protocol plus its header bytes (the result of walking v6 ext headers).
type L4Slice<'a> = (IpProtocol, &'a [u8]);

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
    /// The interface IPv4 address (must match the TUN's assigned address).
    pub address: Ipv4Addr,
    /// Prefix length of the IPv4 TUN subnet (on-link reach for app replies).
    pub prefix: u8,
    /// The interface IPv6 address, if the TUN carries IPv6 (`None` = v4-only).
    pub address6: Option<Ipv6Addr>,
    /// Prefix length of the IPv6 TUN subnet.
    pub prefix6: u8,
    /// TUN MTU.
    pub mtu: usize,
    /// Buffer/flow caps (defaulted; tunable for the iOS memory budget).
    pub limits: Limits,
}

impl Config {
    /// An IPv4-only config with default limits, mirroring the original API.
    #[must_use]
    pub fn new(address: Ipv4Addr, prefix: u8, mtu: usize) -> Self {
        Self {
            address,
            prefix,
            address6: None,
            prefix6: 64,
            mtu,
            limits: Limits::default(),
        }
    }
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

/// The channels a front-end uses to drive the netstack. The netstack stays
/// Hysteria-agnostic: only plain TCP flows and UDP datagrams cross this seam.
pub(crate) struct StackHandle {
    pub(crate) tcp_flows: mpsc::Receiver<TcpFlow>,
    pub(crate) udp_in: mpsc::Receiver<UdpInbound>,
    pub(crate) udp_out: mpsc::Sender<UdpOutbound>,
}

/// Start the netstack over `device`. The background task runs until `device`
/// errors or `shutdown` flips/closes; it ends by dropping all senders.
pub(crate) fn start(
    device: Arc<AsyncDevice>,
    config: Config,
    shutdown: watch::Receiver<bool>,
) -> StackHandle {
    let mut tun_device = TunDevice::new(config.mtu);
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut tun_device,
        Instant::now(),
    );
    // Accept packets destined to any address, not just our own (transparent
    // forwarding), and place our addresses on-link so app-bound replies route
    // back. `any_ip` short-circuits the on-link check for both v4 and v6.
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddr::V4(config.address).into(),
            config.prefix,
        ));
        if let Some(addr6) = config.address6 {
            let _ = addrs.push(IpCidr::new(IpAddr::V6(addr6).into(), config.prefix6));
        }
    });
    let _ = iface.routes_mut().add_default_ipv4_route(config.address);
    if let Some(addr6) = config.address6 {
        let _ = iface.routes_mut().add_default_ipv6_route(addr6);
    }

    let shared: SharedRef = Arc::new(Mutex::new(Shared {
        iface,
        sockets: SocketSet::new(Vec::new()),
        device: tun_device,
    }));
    let notify = Arc::new(Notify::new());
    // Size the flow channel to the flow cap so `try_reserve` only refuses a SYN
    // when we are genuinely at `max_tcp_flows`, not at an unrelated smaller bound.
    let (flow_tx, flow_rx) = mpsc::channel::<TcpFlow>(config.limits.max_tcp_flows);
    let (udp_in_tx, udp_in_rx) = mpsc::channel::<UdpInbound>(256);
    let (udp_out_tx, udp_out_rx) = mpsc::channel::<UdpOutbound>(256);

    let netstack = Netstack {
        device,
        shared,
        notify,
        flow_tx,
        udp_in_tx,
        udp_out_rx,
        shutdown,
        handles: HashMap::new(),
        udp_sockets: UdpSockets::new(),
        limits: config.limits,
        mtu: config.mtu,
    };
    tokio::spawn(netstack.run());

    StackHandle {
        tcp_flows: flow_rx,
        udp_in: udp_in_rx,
        udp_out: udp_out_tx,
    }
}

/// The netstack background task and everything it owns exclusively.
struct Netstack {
    device: Arc<AsyncDevice>,
    shared: SharedRef,
    notify: Arc<Notify>,
    flow_tx: mpsc::Sender<TcpFlow>,
    udp_in_tx: mpsc::Sender<UdpInbound>,
    udp_out_rx: mpsc::Receiver<UdpOutbound>,
    shutdown: watch::Receiver<bool>,
    /// One TCP socket per live flow; the map dedups SYN retransmits.
    handles: Handles,
    /// One UDP socket per live destination (see [`crate::udp`]).
    udp_sockets: UdpSockets,
    limits: Limits,
    mtu: usize,
}

impl Netstack {
    /// Poll, detect flows, and shuttle packets to/from the TUN until the device
    /// errors or shutdown is signalled.
    async fn run(mut self) {
        let mut buf = vec![0u8; self.mtu.max(1500)];
        let mut scratch = vec![0u8; UDP_SCRATCH];
        // UDP replies pulled off `udp_out_rx` in the select, dispatched into
        // smoltcp at the top of the next locked block (never across an await).
        let mut pending_out: Vec<UdpOutbound> = Vec::new();

        loop {
            let poll_delay = {
                let mut guard = lock(&self.shared);
                let s = &mut *guard;
                let now = Instant::now();
                let wall = StdInstant::now();

                for out in pending_out.drain(..) {
                    self.udp_sockets
                        .dispatch_outbound(s, &out, &self.limits, wall);
                }
                detect(
                    s,
                    &mut self.handles,
                    &mut self.udp_sockets,
                    &self.notify,
                    &self.shared,
                    &self.flow_tx,
                    &self.limits,
                    wall,
                );
                s.iface.poll(now, &mut s.device, &mut s.sockets);
                self.udp_sockets
                    .drain_inbound(s, &self.udp_in_tx, &mut scratch, wall);
                reap_finished(s, &mut self.handles);
                self.udp_sockets.reap_idle(s, wall, UDP_IDLE);
                s.iface.poll_delay(now, &s.sockets)
            };

            // Flush everything smoltcp produced out to the TUN.
            loop {
                let packet = lock(&self.shared).device.pop_outbound();
                match packet {
                    Some(packet) => {
                        if self.device.send(&packet).await.is_err() {
                            return;
                        }
                    },
                    None => break,
                }
            }

            // smoltcp's recommended loop: a zero delay means "work is due now", so
            // re-poll immediately rather than arming a `sleep(0)` that hot-loops.
            // Yield first, though: if the outbound flush above sent nothing there
            // was no await this iteration, and on a current-thread runtime a run of
            // zero-delay re-polls would starve the relay tasks sharing the executor.
            let timeout = match poll_delay {
                Some(delay) if delay.total_micros() == 0 => {
                    tokio::task::yield_now().await;
                    continue;
                },
                Some(delay) => Duration::from_micros(delay.total_micros()),
                None => IDLE_POLL,
            };
            tokio::select! {
                read = self.device.recv(&mut buf) => match read {
                    Ok(n) => lock(&self.shared).device.push_inbound(buf[..n].to_vec()),
                    Err(_) => return,
                },
                () = self.notify.notified() => {},
                Some(out) = self.udp_out_rx.recv() => {
                    pending_out.push(out);
                    while let Ok(more) = self.udp_out_rx.try_recv() {
                        pending_out.push(more);
                    }
                },
                _ = self.shutdown.changed() => return,
                () = tokio::time::sleep(timeout) => {},
            }
        }
    }
}

/// A new flow detected from the next inbound packet.
enum Detected {
    /// A TCP connection opening (SYN, no ACK).
    TcpSyn { src: SocketAddr, dst: SocketAddr },
    /// A UDP datagram to `dst` (the source is recovered from the socket later).
    Udp { dst: SocketAddr },
}

/// If the next inbound packet opens a new flow, set it up: create a listening TCP
/// socket and hand the flow to the relay (mirrors Go's `tun.Handler`), or bind a
/// UDP socket on the destination so the upcoming poll delivers the datagram.
#[expect(
    clippy::too_many_arguments,
    reason = "netstack task state, threaded in"
)]
fn detect(
    s: &mut Shared,
    handles: &mut Handles,
    udp_sockets: &mut UdpSockets,
    notify: &Arc<Notify>,
    shared: &SharedRef,
    flow_tx: &mpsc::Sender<TcpFlow>,
    limits: &Limits,
    now: StdInstant,
) {
    // `classify` returns owned addresses, so the borrow of the peeked packet ends
    // before we mutate `s`.
    let Some(detected) = s.device.peek_inbound().and_then(classify) else {
        return;
    };
    let serviced = match detected {
        Detected::TcpSyn { src, dst } => {
            accept_tcp(s, handles, notify, shared, flow_tx, limits, src, dst)
        },
        Detected::Udp { dst } => udp_sockets.ensure(s, dst, limits, now),
    };
    // If no socket will handle this packet (backlog full), drop it before the
    // poll so smoltcp doesn't RST/ICMP-reject it — the client just retransmits.
    if !serviced {
        s.device.pop_inbound();
    }
}

/// Create the listening TCP socket for a new flow and hand it to the relay.
/// Returns whether the SYN will be serviced (a socket now listens, or one already
/// does for a retransmit); `false` means the caller should drop the packet.
#[expect(
    clippy::too_many_arguments,
    reason = "netstack task state, threaded in"
)]
fn accept_tcp(
    s: &mut Shared,
    handles: &mut Handles,
    notify: &Arc<Notify>,
    shared: &SharedRef,
    flow_tx: &mpsc::Sender<TcpFlow>,
    limits: &Limits,
    src: SocketAddr,
    dst: SocketAddr,
) -> bool {
    if handles.values().any(|f| f.key == (src, dst)) {
        return true; // already tracking this flow; its socket handles the SYN retransmit
    }
    if handles.len() >= limits.max_tcp_flows {
        return false; // backlog full: caller drops the SYN, like a real listener
    }

    // Reserve a channel slot *before* creating the socket/stream, so a full relay
    // backlog (or a gone receiver) never drops a `TcpStream` while we hold the
    // `Shared` lock — its `Drop` re-locks the same non-reentrant mutex.
    let Ok(permit) = flow_tx.try_reserve() else {
        return false;
    };

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; limits.tcp_rx_buffer]),
        tcp::SocketBuffer::new(vec![0u8; limits.tcp_tx_buffer]),
    );
    socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
    socket.set_timeout(Some(TCP_TIMEOUT));
    let endpoint = IpListenEndpoint {
        addr: Some(dst.ip().into()),
        port: dst.port(),
    };
    if socket.listen(endpoint).is_err() {
        return false;
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
    true
}

/// Remove sockets whose relay stream has dropped *and* whose close handshake has
/// finished — both conditions required. The liveness token failing to upgrade
/// means the `TcpStream` is gone, so the handle is unreferenced (smoltcp recycles
/// slots, which would otherwise cross-wire a live stream onto another flow). The
/// socket reaching `Closed` means the FIN/ACK exchange that `Drop`'s `close()`
/// began has completed; reaping earlier (in FIN-WAIT/TIME-WAIT) would make smoltcp
/// answer the peer's FIN-ACK with a RST instead of a clean close. smoltcp drives
/// TIME-WAIT to `Closed` on its own (~10 s timer), and our per-socket `set_timeout`
/// aborts a half-closed-but-silent peer, so this always converges.
fn reap_finished(s: &mut Shared, handles: &mut Handles) {
    let finished: Vec<SocketHandle> = handles
        .iter()
        .filter(|(handle, flow)| {
            flow.alive.upgrade().is_none()
                && s.sockets.get::<tcp::Socket<'_>>(**handle).state() == tcp::State::Closed
        })
        .map(|(&handle, _)| handle)
        .collect();
    for handle in finished {
        s.sockets.remove(handle);
        handles.remove(&handle);
    }
}

/// Classify the next inbound packet: a new TCP connection, a UDP datagram, or
/// neither. Handles IPv4 and IPv6 (walking v6 extension headers to the L4 header).
fn classify(packet: &[u8]) -> Option<Detected> {
    let (proto, src_ip, dst_ip, l4) = parse_ip(packet)?;
    match proto {
        IpProtocol::Tcp => {
            let segment = TcpPacket::new_checked(l4).ok()?;
            if !segment.syn() || segment.ack() {
                return None;
            }
            Some(Detected::TcpSyn {
                src: SocketAddr::new(src_ip, segment.src_port()),
                dst: SocketAddr::new(dst_ip, segment.dst_port()),
            })
        },
        IpProtocol::Udp => {
            let datagram = UdpPacket::new_checked(l4).ok()?;
            Some(Detected::Udp {
                dst: SocketAddr::new(dst_ip, datagram.dst_port()),
            })
        },
        _ => None,
    }
}

/// Parse an IP packet down to its L4 header: returns `(protocol, src, dst, l4)`.
/// IPv6 extension headers are walked (capped) to reach TCP/UDP; fragments and
/// other non-skippable headers yield `None`.
fn parse_ip(packet: &[u8]) -> Option<Parsed<'_>> {
    match packet.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            Some((
                ip.next_header(),
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.payload(),
            ))
        },
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            let (proto, l4) = walk_ipv6(ip.next_header(), ip.payload())?;
            Some((
                proto,
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                l4,
            ))
        },
        _ => None,
    }
}

/// Walk the IPv6 extension-header chain to the L4 header. Skips the standard
/// option-bearing headers; stops (returning `None`) at a fragment, authentication
/// header, `ICMPv6`, or anything unrecognized — none of which carry a flow-opening
/// L4 header we can act on.
fn walk_ipv6(mut proto: IpProtocol, mut data: &[u8]) -> Option<L4Slice<'_>> {
    for _ in 0..MAX_EXT_HEADERS {
        match proto {
            IpProtocol::Tcp | IpProtocol::Udp => return Some((proto, data)),
            IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                let ext = Ipv6ExtHeader::new_checked(data).ok()?;
                let next = ext.next_header();
                // Header length is in 8-octet units, not counting the first 8.
                let total = usize::from(ext.header_len()) * 8 + 8;
                proto = next;
                data = data.get(total..)?;
            },
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;

    use super::*;

    /// Build a minimal IPv4 packet with the given L4 protocol and a 4-byte body.
    fn ipv4(protocol: u8, body: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + body.len()];
        pkt[0] = 0x45; // IPv4, IHL 5 (20-byte header)
        let total = u16::try_from(pkt.len()).unwrap_or(0);
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src addr
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]); // dst addr
        pkt[20..].copy_from_slice(body);
        pkt
    }

    /// Build a minimal IPv6 packet with the given next-header and body.
    fn ipv6(next_header: u8, body: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + body.len()];
        pkt[0] = 0x60; // IPv6
        let payload_len = u16::try_from(body.len()).unwrap_or(0);
        pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
        pkt[6] = next_header;
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // src
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]); // dst
        pkt[40..].copy_from_slice(body);
        pkt
    }

    /// A 20-byte TCP header with the given flag bits (SYN = 0x02, ACK = 0x10).
    fn tcp_header(syn: bool, ack: bool) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes()); // src port
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes()); // dst port
        tcp[12] = 0x50; // data offset 5, no options
        tcp[13] = (u8::from(syn) * 0x02) | (u8::from(ack) * 0x10);
        tcp
    }

    /// An 8-byte UDP header (no payload) to ports 40000 → 53.
    fn udp_header() -> Vec<u8> {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes()); // src port
        udp[2..4].copy_from_slice(&53u16.to_be_bytes()); // dst port
        udp[4..6].copy_from_slice(&8u16.to_be_bytes()); // length
        udp
    }

    #[test]
    fn classifies_ipv4_tcp_syn() -> Result<()> {
        let Some(Detected::TcpSyn { src, dst }) = classify(&ipv4(6, &tcp_header(true, false)))
        else {
            return Err(anyhow!("expected a TCP SYN"));
        };
        assert_eq!(src, "10.0.0.2:40000".parse()?, "source 5-tuple");
        assert_eq!(dst, "93.184.216.34:443".parse()?, "destination 5-tuple");
        Ok(())
    }

    #[test]
    fn classifies_ipv6_tcp_syn() -> Result<()> {
        let Some(Detected::TcpSyn { src, dst }) = classify(&ipv6(6, &tcp_header(true, false)))
        else {
            return Err(anyhow!("expected a TCP SYN"));
        };
        assert_eq!(src, "[2001::2]:40000".parse()?, "v6 source 5-tuple");
        assert_eq!(dst, "[2001::9]:443".parse()?, "v6 destination 5-tuple");
        Ok(())
    }

    #[test]
    fn classifies_ipv6_tcp_behind_ext_headers() -> Result<()> {
        // Hop-by-Hop (8 bytes: next=Routing, len=0, padding) then Routing (8
        // bytes: next=TCP, len=0) then the TCP SYN.
        let mut body = vec![43u8, 0, 0, 0, 0, 0, 0, 0]; // HopByHop -> Routing(43)
        body.extend_from_slice(&[6u8, 0, 0, 0, 0, 0, 0, 0]); // Routing -> TCP(6)
        body.extend_from_slice(&tcp_header(true, false));
        let Some(Detected::TcpSyn { dst, .. }) = classify(&ipv6(0, &body)) else {
            return Err(anyhow!("expected a TCP SYN behind ext headers"));
        };
        assert_eq!(
            dst,
            "[2001::9]:443".parse()?,
            "5-tuple found past ext headers"
        );
        Ok(())
    }

    #[test]
    fn classifies_udp() -> Result<()> {
        let Some(Detected::Udp { dst }) = classify(&ipv4(17, &udp_header())) else {
            return Err(anyhow!("expected a UDP datagram"));
        };
        assert_eq!(dst, "93.184.216.34:53".parse()?, "v4 UDP destination");
        let Some(Detected::Udp { dst }) = classify(&ipv6(17, &udp_header())) else {
            return Err(anyhow!("expected a v6 UDP datagram"));
        };
        assert_eq!(dst, "[2001::9]:53".parse()?, "v6 UDP destination");
        Ok(())
    }

    #[test]
    fn ignores_non_syn_and_garbage() {
        assert!(
            classify(&ipv4(6, &tcp_header(true, true))).is_none(),
            "SYN-ACK ignored"
        );
        assert!(
            classify(&ipv4(6, &tcp_header(false, true))).is_none(),
            "ACK ignored"
        );
        assert!(
            classify(&ipv6(44, &udp_header())).is_none(),
            "v6 fragment ignored"
        );
        assert!(classify(&ipv4(1, &[0u8; 8])).is_none(), "ICMP ignored");
        assert!(classify(&[]).is_none(), "empty ignored");
        assert!(classify(&[0x60]).is_none(), "truncated v6 ignored");
    }
}
