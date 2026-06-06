//! Per-source UDP NAT over the Hysteria client (the orchestration side).
//!
//! Mirrors the Go TUN handler: one Hysteria UDP session per app *source*
//! endpoint, multiplexing every destination through it (the destination rides
//! each datagram's address). A per-session task pumps replies back out as
//! [`UdpOutbound`]. Sessions idle for [`crate::stack::UDP_IDLE`] are reaped.
//!
//! The map is abstracted over [`UdpRelay`] (implemented for the Hysteria
//! `UdpConn`) so the NAT/GC logic is unit-testable with a fake relay.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use hysteria::client::transport::QuinnUdpIo;
use hysteria::client::udp::UdpConn;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::udp::UdpOutbound;

/// A received datagram: payload plus the source address it came from, as a string.
type Datagram = (Vec<u8>, String);

/// One UDP relay session: send a datagram to an address, and receive replies. A
/// thin seam over the Hysteria `UdpConn` so the session map can be tested with a
/// fake.
pub(crate) trait UdpRelay: Send + Sync + 'static {
    /// Send `data` to `addr` (e.g. `"1.2.3.4:53"`); `false` on transport error.
    fn send(&self, data: &[u8], addr: &str) -> bool;
    /// The next datagram as `(data, source-addr-string)`, or `None` once closed.
    fn receive(&self) -> impl Future<Output = Option<Datagram>> + Send;
}

impl UdpRelay for UdpConn<QuinnUdpIo> {
    fn send(&self, data: &[u8], addr: &str) -> bool {
        UdpConn::send(self, data, addr).is_ok()
    }
    async fn receive(&self) -> Option<Datagram> {
        UdpConn::receive(self).await.ok()
    }
}

/// Shared bits a per-session receive task needs.
pub(crate) struct RecvCtx {
    pub(crate) udp_out: mpsc::Sender<UdpOutbound>,
    pub(crate) shutdown: watch::Receiver<bool>,
    /// Bytes received from remotes (server→app), tallied at the seam.
    pub(crate) rx: Arc<AtomicU64>,
    /// Cumulative count of UDP sessions opened.
    pub(crate) sessions: Arc<AtomicU64>,
}

struct Entry<R> {
    conn: Arc<R>,
    last_activity: Instant,
    task: JoinHandle<()>,
}

/// UDP sessions keyed by app source endpoint (the NAT key).
pub(crate) struct Sessions<R: UdpRelay> {
    map: HashMap<SocketAddr, Entry<R>>,
}

impl<R: UdpRelay> Sessions<R> {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// The session for `src`, creating one (via `create`) and spawning its reply
    /// task on first use. Returns `None` if `create` fails (e.g. UDP disabled).
    pub(crate) fn get_or_create<F>(
        &mut self,
        src: SocketAddr,
        now: Instant,
        ctx: &RecvCtx,
        create: F,
    ) -> Option<Arc<R>>
    where
        F: FnOnce() -> Option<Arc<R>>,
    {
        if let Some(entry) = self.map.get_mut(&src) {
            entry.last_activity = now;
            return Some(Arc::clone(&entry.conn));
        }
        let conn = create()?;
        ctx.sessions.fetch_add(1, Ordering::Relaxed);
        let task = spawn_recv(
            Arc::clone(&conn),
            src,
            ctx.udp_out.clone(),
            ctx.shutdown.clone(),
            Arc::clone(&ctx.rx),
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

    /// Drop sessions idle longer than `idle` (closing the Hysteria session and
    /// stopping its reply task).
    pub(crate) fn reap_idle(&mut self, now: Instant, idle: Duration) {
        for src in idle_keys(&self.map, now, idle) {
            if let Some(entry) = self.map.remove(&src) {
                entry.task.abort();
                // Dropping `entry.conn` (the map's last strong ref once the task
                // is aborted) runs `UdpConn::Drop`, closing the session.
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

impl<R: UdpRelay> Drop for Sessions<R> {
    fn drop(&mut self) {
        for entry in self.map.values() {
            entry.task.abort();
        }
    }
}

/// Pump a session's replies out as [`UdpOutbound`] until it closes or shutdown.
fn spawn_recv<R: UdpRelay>(
    conn: Arc<R>,
    src: SocketAddr,
    udp_out: mpsc::Sender<UdpOutbound>,
    mut shutdown: watch::Receiver<bool>,
    rx: Arc<AtomicU64>,
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
                    rx.fetch_add(u64::try_from(data.len()).unwrap_or(u64::MAX), Ordering::Relaxed);
                    if udp_out.send(UdpOutbound { src, from, data }).await.is_err() {
                        break; // netstack gone
                    }
                },
                _ = shutdown.changed() => break,
            }
        }
    })
}

/// Sessions idle longer than `idle`. Pure, so the GC policy is testable.
fn idle_keys<R>(
    map: &HashMap<SocketAddr, Entry<R>>,
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

    /// A relay whose `receive` never resolves, so the session task stays alive.
    struct FakeRelay {
        sent: Mutex<Vec<Datagram>>,
    }

    impl UdpRelay for FakeRelay {
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

    type Harness = (RecvCtx, mpsc::Receiver<UdpOutbound>);

    fn ctx() -> Harness {
        let (udp_out, rx_chan) = mpsc::channel(8);
        let (_tx, shutdown) = watch::channel(false);
        let ctx = RecvCtx {
            udp_out,
            shutdown,
            rx: Arc::new(AtomicU64::new(0)),
            sessions: Arc::new(AtomicU64::new(0)),
        };
        (ctx, rx_chan)
    }

    #[tokio::test]
    async fn get_or_create_dedups_by_source() -> Result<()> {
        let (ctx, _rx) = ctx();
        let mut sessions: Sessions<FakeRelay> = Sessions::new();
        let src: SocketAddr = "10.0.0.2:40000".parse()?;
        let now = Instant::now();

        let make = || {
            Some(Arc::new(FakeRelay {
                sent: Mutex::new(Vec::new()),
            }))
        };
        let a = sessions
            .get_or_create(src, now, &ctx, make)
            .ok_or_else(|| anyhow!("first create failed"))?;
        let b = sessions
            .get_or_create(src, now, &ctx, make)
            .ok_or_else(|| anyhow!("second lookup failed"))?;

        assert!(Arc::ptr_eq(&a, &b), "same source reuses one session");
        assert_eq!(sessions.len(), 1, "one session for one source");
        assert_eq!(ctx.sessions.load(Ordering::Relaxed), 1, "counted one open");
        Ok(())
    }

    #[tokio::test]
    async fn reap_idle_drops_stale_sessions() -> Result<()> {
        let (ctx, _rx) = ctx();
        let mut sessions: Sessions<FakeRelay> = Sessions::new();
        let src: SocketAddr = "10.0.0.2:40000".parse()?;
        let start = Instant::now();

        sessions
            .get_or_create(src, start, &ctx, || {
                Some(Arc::new(FakeRelay {
                    sent: Mutex::new(Vec::new()),
                }))
            })
            .ok_or_else(|| anyhow!("create failed"))?;
        assert_eq!(sessions.len(), 1, "session present");

        // 301 s later with a 300 s idle window → reaped.
        sessions.reap_idle(start + Duration::from_secs(301), Duration::from_mins(5));
        assert_eq!(sessions.len(), 0, "stale session reaped");
        Ok(())
    }
}
