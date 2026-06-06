//! Transparent UDP forwarding over smoltcp (the netstack side).
//!
//! A smoltcp UDP socket binds to a *destination* endpoint and receives datagrams
//! from many senders; its inbound metadata names the sender (the app's source)
//! and reply sends can spoof the source address. So we keep one socket per
//! destination endpoint and demultiplex app sources from the metadata. The
//! netstack task owns this table exclusively (like the TCP `handles` map) and
//! never touches Hysteria — it only lifts datagrams out as [`UdpInbound`] and
//! injects replies from [`UdpOutbound`]. The per-source NAT (one Hysteria UDP
//! session per app source) lives on the orchestration side ([`crate::session`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use smoltcp::iface::SocketHandle;
use smoltcp::phy::PacketMeta;
use smoltcp::socket::udp;
use tokio::sync::mpsc;

use crate::stack::Limits;
use crate::stack::Shared;

/// A datagram from the app to a remote, lifted out of the netstack. `src` is the
/// app's source endpoint (the per-source NAT key); `dst` is the original
/// destination it addressed.
pub(crate) struct UdpInbound {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) data: Vec<u8>,
}

/// A datagram from a remote back to the app, to inject into the netstack. `src`
/// is the app endpoint to deliver to; `from` is the remote it came from, which we
/// spoof as the reply's source so the app sees an answer from where it asked.
pub(crate) struct UdpOutbound {
    pub(crate) src: SocketAddr,
    pub(crate) from: SocketAddr,
    pub(crate) data: Vec<u8>,
}

/// One transparent-UDP socket bound to a destination endpoint, plus the last time
/// a datagram crossed it in either direction (for idle reaping).
struct UdpEntry {
    handle: SocketHandle,
    last_activity: Instant,
}

/// The netstack task's UDP socket table, keyed by destination endpoint.
pub(crate) struct UdpSockets {
    map: HashMap<SocketAddr, UdpEntry>,
}

impl UdpSockets {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Bind a UDP socket to `dst` if not already present, so the next poll
    /// delivers datagrams addressed there. Returns `false` only when at capacity
    /// (the datagram is then dropped, as a real stack would under pressure).
    pub(crate) fn ensure(
        &mut self,
        s: &mut Shared,
        dst: SocketAddr,
        limits: &Limits,
        now: Instant,
    ) -> bool {
        if let Some(entry) = self.map.get_mut(&dst) {
            entry.last_activity = now;
            return true;
        }
        if self.map.len() >= limits.max_udp_sockets {
            return false;
        }
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; limits.udp_packets],
                vec![0u8; limits.udp_rx_buffer],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; limits.udp_packets],
                vec![0u8; limits.udp_tx_buffer],
            ),
        );
        // Bind to the exact destination (addr + port): `accepts()` then admits
        // only datagrams to this destination, from any source.
        if socket.bind(dst).is_err() {
            return false;
        }
        let handle = s.sockets.add(socket);
        self.map.insert(
            dst,
            UdpEntry {
                handle,
                last_activity: now,
            },
        );
        true
    }

    /// Drain every UDP socket's receive queue after a poll, lifting each datagram
    /// out as [`UdpInbound`]. Uses `try_send` (never awaits, so it is sound under
    /// the netstack mutex) and drops on a full channel — UDP is lossy.
    pub(crate) fn drain_inbound(
        &mut self,
        s: &mut Shared,
        tx: &mpsc::Sender<UdpInbound>,
        scratch: &mut [u8],
        now: Instant,
    ) {
        for (&dst, entry) in &mut self.map {
            let socket = s.sockets.get_mut::<udp::Socket<'_>>(entry.handle);
            while socket.can_recv() {
                let Ok((n, meta)) = socket.recv_slice(scratch) else {
                    break;
                };
                entry.last_activity = now;
                let Some(slice) = scratch.get(..n) else {
                    continue;
                };
                let inbound = UdpInbound {
                    src: meta.endpoint.into(),
                    dst,
                    data: slice.to_vec(),
                };
                // Drop on a full channel: the orchestration side is behind, and
                // UDP tolerates loss better than head-of-line blocking the task.
                let _ = tx.try_send(inbound);
            }
        }
    }

    /// Inject a reply datagram toward the app, spoofing its source as the remote
    /// the app originally addressed (`out.from`). Ensures the destination socket
    /// exists first (it normally does, from the outbound packet that triggered
    /// the reply).
    pub(crate) fn dispatch_outbound(
        &mut self,
        s: &mut Shared,
        out: &UdpOutbound,
        limits: &Limits,
        now: Instant,
    ) {
        if !self.ensure(s, out.from, limits, now) {
            return;
        }
        let Some(entry) = self.map.get_mut(&out.from) else {
            return;
        };
        let socket = s.sockets.get_mut::<udp::Socket<'_>>(entry.handle);
        let meta = udp::UdpMetadata {
            endpoint: out.src.into(),
            // The reply's source address: the remote the app talked to.
            local_address: Some(out.from.ip().into()),
            meta: PacketMeta::default(),
        };
        if socket.send_slice(&out.data, meta).is_ok() {
            entry.last_activity = now;
        }
    }

    /// Reap UDP sockets idle in both directions for longer than `idle`.
    pub(crate) fn reap_idle(&mut self, s: &mut Shared, now: Instant, idle: Duration) {
        for dst in idle_keys(&self.map, now, idle) {
            if let Some(entry) = self.map.remove(&dst) {
                s.sockets.remove(entry.handle);
            }
        }
    }
}

/// The destinations whose sockets have been idle longer than `idle`. Pure so the
/// reaping policy is testable without a live `Interface`.
fn idle_keys(map: &HashMap<SocketAddr, UdpEntry>, now: Instant, idle: Duration) -> Vec<SocketAddr> {
    map.iter()
        .filter(|(_, entry)| now.saturating_duration_since(entry.last_activity) > idle)
        .map(|(&dst, _)| dst)
        .collect()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use smoltcp::iface::SocketSet;

    use super::*;

    /// A dummy handle is fine: `idle_keys` never dereferences it.
    fn entry(handle: SocketHandle, last_activity: Instant) -> UdpEntry {
        UdpEntry {
            handle,
            last_activity,
        }
    }

    #[test]
    fn idle_keys_selects_only_stale_sockets() -> Result<()> {
        let mut set = SocketSet::new(Vec::new());
        // A throwaway socket just to mint two distinct handles.
        let mut mint = || {
            set.add(udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0u8; 16]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0u8; 16]),
            ))
        };
        // Build instants by addition only (Instant - Duration can underflow).
        let start = Instant::now();
        let idle = Duration::from_mins(5);
        let fresh: SocketAddr = "1.1.1.1:53".parse()?;
        let stale: SocketAddr = "8.8.8.8:53".parse()?;

        let mut map = HashMap::new();
        map.insert(fresh, entry(mint(), start + Duration::from_mins(5)));
        map.insert(stale, entry(mint(), start));

        // Query 301 s after `start`: `stale` is 301 s idle (> 300), `fresh` 1 s.
        let reaped = idle_keys(&map, start + Duration::from_secs(301), idle);
        assert_eq!(reaped, vec![stale], "only the stale destination is reaped");
        Ok(())
    }
}
