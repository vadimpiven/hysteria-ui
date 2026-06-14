//! Per-source UDP NAT over the Hysteria client (the orchestration side).
//!
//! Mirrors the Go TUN handler: one Hysteria UDP session per app *source*
//! endpoint, multiplexing every destination through it (the destination rides
//! each datagram's address). A per-session task pumps replies back out through
//! the [`Downstream`]. Idle sessions are reaped via
//! [`reap_idle`](Sessions::reap_idle).
//!
//! The map sits between two seams and owns no caller type, so the NAT/GC logic
//! is unit-testable with fakes on both sides:
//!
//! * [`Upstream`] — the duplex link to the Hysteria server (send to a remote,
//!   receive its replies). Implemented for the Hysteria `UdpConn`.
//! * [`Downstream`] — the reply link back toward the app (deliver one datagram).
//!
//! The directions are literal: app→server traffic goes out via the [`Upstream`],
//! server→app replies come back via the [`Downstream`]. Observability stays with
//! the caller — outbound results come back through [`Outcome`], inbound bytes are
//! tallied inside its [`Downstream`].

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use hysteria::client::transport::QuinnUdpIo;
use hysteria::client::udp::UdpConn;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// A received datagram: payload plus the source address it came from, as a string.
type Datagram = (Vec<u8>, String);

/// The upstream seam: the duplex link to the Hysteria server — send a datagram
/// to an address, and receive replies. A thin cover over the Hysteria `UdpConn`
/// so the session map can be tested with a fake.
pub(crate) trait Upstream: Send + Sync + 'static {
    /// Send `data` to `addr` (e.g. `"1.2.3.4:53"`); `false` on transport error.
    fn send(&self, data: &[u8], addr: &str) -> bool;
    /// The next datagram as `(data, source-addr-string)`, or `None` once closed.
    fn receive(&self) -> impl Future<Output = Option<Datagram>> + Send;
}

impl Upstream for UdpConn<QuinnUdpIo> {
    fn send(&self, data: &[u8], addr: &str) -> bool {
        UdpConn::send(self, data, addr).is_ok()
    }
    async fn receive(&self) -> Option<Datagram> {
        UdpConn::receive(self).await.ok()
    }
}

/// The downstream seam, mirroring [`Upstream`]: the reply link back toward the
/// app. Cloned into each per-session task, so the NAT carries no caller type —
/// the tunnel's implementation owns the channel and any byte accounting.
pub(crate) trait Downstream: Clone + Send + Sync + 'static {
    /// Deliver one reply: payload `data` from remote `from`, addressed back to
    /// app source `src`. Returns `false` if the downstream is gone, which stops
    /// the session's reply task.
    fn deliver(
        &self,
        src: SocketAddr,
        from: SocketAddr,
        data: Vec<u8>,
    ) -> impl Future<Output = bool> + Send;
}

/// What [`forward`](Sessions::forward) did with a datagram, for the caller's
/// counters. Carries no counters itself — the NAT stays metric-free.
pub(crate) enum Outcome {
    /// Forwarded to the destination. `opened` is true when this datagram created
    /// the session (so the caller can count newly opened NAT sessions).
    Sent { opened: bool },
    /// Dropped: no session could be opened (UDP disabled or table full) or the
    /// transport send failed. The caller counts this as a flow error.
    Dropped,
}

struct Entry<U> {
    conn: Arc<U>,
    last_activity: Instant,
    task: JoinHandle<()>,
}

/// UDP sessions keyed by app source endpoint (the NAT key).
pub(crate) struct Sessions<U: Upstream, D: Downstream> {
    map: HashMap<SocketAddr, Entry<U>>,
    /// Cap on concurrent sessions; a new source past this is refused (its
    /// datagram is dropped) so a local source-port flood can't grow the map —
    /// and the server's session table — without bound.
    max: usize,
    /// Reply link the per-session tasks pump into.
    downstream: D,
    /// Tripped to stop every reply task on tunnel shutdown.
    shutdown: watch::Receiver<bool>,
}

impl<U: Upstream, D: Downstream> Sessions<U, D> {
    pub(crate) fn new(max: usize, downstream: D, shutdown: watch::Receiver<bool>) -> Self {
        Self {
            map: HashMap::new(),
            max,
            downstream,
            shutdown,
        }
    }

    /// The session for `src`, creating one (via `create`) and spawning its reply
    /// task on first use. Returns `None` if the table is full or `create` fails
    /// (e.g. UDP disabled).
    pub(crate) fn get_or_create<F>(
        &mut self,
        src: SocketAddr,
        now: Instant,
        create: F,
    ) -> Option<Arc<U>>
    where
        F: FnOnce() -> Option<Arc<U>>,
    {
        if let Some(entry) = self.map.get_mut(&src) {
            entry.last_activity = now;
            return Some(Arc::clone(&entry.conn));
        }
        if self.map.len() >= self.max {
            return None; // session table full: drop, like the TCP/UDP-socket caps
        }
        let conn = create()?;
        let task = spawn_recv(
            Arc::clone(&conn),
            src,
            self.downstream.clone(),
            self.shutdown.clone(),
        );
        self.map.insert(
            src,
            Entry {
                conn: Arc::clone(&conn),
                last_activity: now,
                task,
            },
        );
        Some(conn)
    }

    /// Forward one app datagram to `dst` through `src`'s session, opening the
    /// session (via `create`) on first use. The send half of Go's
    /// `NewPacketConnection` (`rc.Send(buffer.Bytes(), addr.String())`); the
    /// receive half is the task spawned in [`get_or_create`](Self::get_or_create).
    pub(crate) fn forward<F>(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        now: Instant,
        create: F,
    ) -> Outcome
    where
        F: FnOnce() -> Option<Arc<U>>,
    {
        let opened = !self.map.contains_key(&src);
        let Some(conn) = self.get_or_create(src, now, create) else {
            return Outcome::Dropped;
        };
        if conn.send(data, &dst.to_string()) {
            Outcome::Sent { opened }
        } else {
            Outcome::Dropped
        }
    }

    /// Drop sessions idle longer than `idle` (closing the Hysteria session and
    /// stopping its reply task).
    pub(crate) fn reap_idle(&mut self, now: Instant, idle: Duration) {
        for src in idle_keys(&self.map, now, idle) {
            if let Some(entry) = self.map.remove(&src) {
                entry.task.abort();
                // `abort` only schedules cancellation: the receive task holds its
                // own `Arc<conn>`, so the session closes (via `UdpConn::Drop`)
                // once the executor drops the aborted task *and* this `entry.conn`
                // — soon after, not synchronously here.
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

impl<U: Upstream, D: Downstream> Drop for Sessions<U, D> {
    fn drop(&mut self) {
        for entry in self.map.values() {
            entry.task.abort();
        }
    }
}

/// Pump a session's replies into the downstream until it closes or shutdown trips.
fn spawn_recv<U: Upstream, D: Downstream>(
    conn: Arc<U>,
    src: SocketAddr,
    downstream: D,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                received = conn.receive() => {
                    let Some((data, from)) = received else {
                        break; // session closed
                    };
                    // The reply's source is the remote we addressed; if it isn't
                    // an ip:port literal we can't spoof it back, so skip it.
                    let Ok(from) = from.parse::<SocketAddr>() else {
                        continue;
                    };
                    if !downstream.deliver(src, from, data).await {
                        break; // downstream gone
                    }
                },
                _ = shutdown.changed() => break,
            }
        }
    })
}

/// Sessions idle longer than `idle`. Pure, so the GC policy is testable.
fn idle_keys<U>(
    map: &HashMap<SocketAddr, Entry<U>>,
    now: Instant,
    idle: Duration,
) -> Vec<SocketAddr> {
    map.iter()
        .filter(|(_, entry)| now.saturating_duration_since(entry.last_activity) > idle)
        .map(|(&src, _)| src)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Result;
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;

    use super::*;

    /// An upstream whose `receive` never resolves, so the session task stays alive.
    struct FakeUpstream {
        sent: Mutex<Vec<Datagram>>,
    }

    impl Upstream for FakeUpstream {
        fn send(&self, data: &[u8], addr: &str) -> bool {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((data.to_vec(), addr.to_string()));
            true
        }
        async fn receive(&self) -> Option<Datagram> {
            std::future::pending().await
        }
    }

    /// Replies a [`FakeDownstream`] was handed: `(src, from, data)` per delivery.
    type Delivered = Arc<Mutex<Vec<(SocketAddr, SocketAddr, Vec<u8>)>>>;

    /// A downstream that records what it was handed; stands in for the tunnel's.
    #[derive(Clone, Default)]
    struct FakeDownstream {
        delivered: Delivered,
    }

    impl Downstream for FakeDownstream {
        async fn deliver(&self, src: SocketAddr, from: SocketAddr, data: Vec<u8>) -> bool {
            self.delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((src, from, data));
            true
        }
    }

    /// A session map plus the live shutdown sender (kept so reply tasks aren't
    /// torn down mid-test) and the downstream (kept for inspection).
    type Harness = (
        Sessions<FakeUpstream, FakeDownstream>,
        watch::Sender<bool>,
        FakeDownstream,
    );

    fn harness(max: usize) -> Harness {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let downstream = FakeDownstream::default();
        let sessions = Sessions::new(max, downstream.clone(), shutdown_rx);
        (sessions, shutdown_tx, downstream)
    }

    fn fake_upstream() -> Option<Arc<FakeUpstream>> {
        Some(Arc::new(FakeUpstream {
            sent: Mutex::new(Vec::new()),
        }))
    }

    #[tokio::test]
    async fn get_or_create_dedups_by_source() -> Result<()> {
        let (mut sessions, _shutdown, _downstream) = harness(usize::MAX);
        let src: SocketAddr = "10.0.0.2:40000".parse()?;
        let now = Instant::now();

        let a = sessions
            .get_or_create(src, now, fake_upstream)
            .ok_or_else(|| anyhow!("first create failed"))?;
        let b = sessions
            .get_or_create(src, now, fake_upstream)
            .ok_or_else(|| anyhow!("second lookup failed"))?;

        assert!(Arc::ptr_eq(&a, &b), "same source reuses one session");
        assert_eq!(sessions.len(), 1, "one session for one source");
        Ok(())
    }

    #[tokio::test]
    async fn reap_idle_drops_stale_sessions() -> Result<()> {
        let (mut sessions, _shutdown, _downstream) = harness(usize::MAX);
        let src: SocketAddr = "10.0.0.2:40000".parse()?;
        let start = Instant::now();

        sessions
            .get_or_create(src, start, fake_upstream)
            .ok_or_else(|| anyhow!("create failed"))?;
        assert_eq!(sessions.len(), 1, "session present");

        // 301 s later with a 300 s idle window → reaped.
        sessions.reap_idle(start + Duration::from_secs(301), Duration::from_mins(5));
        assert_eq!(sessions.len(), 0, "stale session reaped");
        Ok(())
    }

    #[tokio::test]
    async fn forward_sends_datagram_and_reports_open() -> Result<()> {
        let (mut sessions, _shutdown, _downstream) = harness(usize::MAX);
        let src: SocketAddr = "10.0.0.2:40000".parse()?;
        let dst: SocketAddr = "1.1.1.1:53".parse()?;
        let relay = Arc::new(FakeUpstream {
            sent: Mutex::new(Vec::new()),
        });
        let made = Arc::clone(&relay);

        let first = sessions.forward(src, dst, b"hi", Instant::now(), move || Some(made));
        assert!(
            matches!(first, Outcome::Sent { opened: true }),
            "first datagram opens the session and is sent"
        );
        // A second datagram from the same source reuses the session (not opened).
        let again = sessions.forward(src, dst, b"yo", Instant::now(), fake_upstream);
        assert!(
            matches!(again, Outcome::Sent { opened: false }),
            "reused source is sent without re-opening"
        );

        let recorded = relay
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            *recorded,
            vec![
                (b"hi".to_vec(), "1.1.1.1:53".to_string()),
                (b"yo".to_vec(), "1.1.1.1:53".to_string()),
            ],
            "both payloads went to the destination address"
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_new_source_when_session_table_is_full() -> Result<()> {
        let (mut sessions, _shutdown, _downstream) = harness(1);
        let now = Instant::now();

        let first: SocketAddr = "10.0.0.2:40000".parse()?;
        assert!(
            sessions.get_or_create(first, now, fake_upstream).is_some(),
            "first source opens a session"
        );
        let second: SocketAddr = "10.0.0.2:40001".parse()?;
        assert!(
            sessions.get_or_create(second, now, fake_upstream).is_none(),
            "a new source past the cap is refused"
        );
        // The already-open source is still served (the cap only blocks new ones).
        assert!(
            sessions.get_or_create(first, now, fake_upstream).is_some(),
            "an existing source is unaffected by the cap"
        );
        assert_eq!(sessions.len(), 1, "the cap held the table at one session");
        Ok(())
    }
}
