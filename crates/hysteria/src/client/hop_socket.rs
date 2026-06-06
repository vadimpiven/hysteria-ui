//! A quinn `AsyncUdpSocket` that hops the destination UDP port over a range to
//! defeat port-based blocking. Port of `extras/transport/udphop/conn.go`.
//!
//! Difference from Go: Go also rebinds a fresh *local* socket on each hop; quinn
//! owns its socket, so we rotate only the *destination* port over a single local
//! socket — the primary anti-censorship mechanism. quinn still sees a stable peer
//! (`canonical`) because inbound source addresses are normalized to it (Go's
//! `ReadFrom` likewise reports the canonical addr).

use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use quinn::AsyncUdpSocket;
use quinn::UdpPoller;
use quinn::udp::RecvMeta;
use quinn::udp::Transmit;
use rand::Rng as _;

use crate::client::config::HopIntervalConfig;

/// Wraps an inner [`AsyncUdpSocket`], rewriting each outbound datagram's
/// destination to the current hop port and normalizing inbound source addresses
/// to `canonical`.
pub struct HopUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    canonical: SocketAddr,
    state: Arc<HopState>,
}

struct HopState {
    addrs: Vec<SocketAddr>,
    index: AtomicUsize,
}

impl HopUdpSocket {
    /// `addrs` must be non-empty. Spawns a background task that re-randomizes the
    /// active port every hop interval; it stops when the socket is dropped.
    pub fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        canonical: SocketAddr,
        addrs: Vec<SocketAddr>,
        interval: HopIntervalConfig,
    ) -> Self {
        let start = rand::rng().random_range(0..addrs.len());
        let state = Arc::new(HopState {
            addrs,
            index: AtomicUsize::new(start),
        });
        tokio::spawn(hop_loop(Arc::downgrade(&state), interval));
        Self {
            inner,
            canonical,
            state,
        }
    }

    fn current(&self) -> SocketAddr {
        self.state.addrs[self.state.index.load(Ordering::Relaxed)]
    }
}

impl fmt::Debug for HopUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopUdpSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for HopUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // Always write to the current hop port (Go writes to Addrs[addrIndex]).
        let hopped = Transmit {
            destination: self.current(),
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&hopped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &result {
            // Present every datagram as coming from the canonical peer so quinn
            // keeps matching this connection across hops.
            for m in meta.iter_mut().take(*count) {
                m.addr = self.canonical;
            }
        }
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Re-randomize the active port every hop interval until the socket is dropped.
async fn hop_loop(state: Weak<HopState>, interval: HopIntervalConfig) {
    loop {
        tokio::time::sleep(next_delay(interval)).await;
        let Some(state) = state.upgrade() else {
            return; // socket dropped
        };
        let index = rand::rng().random_range(0..state.addrs.len());
        state.index.store(index, Ordering::Relaxed);
    }
}

/// A random delay in `[min, max]` (Go's `nextHopInterval`:
/// `Min + rand.Int63n(int64(Max-Min)+1)` — inclusive, nanosecond resolution).
fn next_delay(interval: HopIntervalConfig) -> std::time::Duration {
    if interval.min >= interval.max {
        return interval.min;
    }
    let span = interval.max.saturating_sub(interval.min).as_nanos();
    let span = u64::try_from(span).unwrap_or(u64::MAX);
    interval.min + std::time::Duration::from_nanos(rand::rng().random_range(0..=span))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn next_delay_with_equal_bounds_is_constant() {
        let interval = HopIntervalConfig {
            min: Duration::from_secs(7),
            max: Duration::from_secs(7),
        };
        assert_eq!(
            next_delay(interval),
            Duration::from_secs(7),
            "equal bounds ⇒ exactly that delay",
        );
    }

    #[test]
    fn next_delay_stays_within_inclusive_bounds() {
        let interval = HopIntervalConfig {
            min: Duration::from_secs(10),
            max: Duration::from_secs(30),
        };
        for _ in 0..1000 {
            let d = next_delay(interval);
            assert!(
                d >= interval.min && d <= interval.max,
                "delay {d:?} within [{:?}, {:?}]",
                interval.min,
                interval.max,
            );
        }
    }
}
