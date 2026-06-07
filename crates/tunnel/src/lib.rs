//! Userspace TUN netstack that drives the Hysteria 2 client.
//!
//! Bridges a TUN device (raw IP packets) to the `hysteria` client: a smoltcp
//! netstack accepts each flow to an arbitrary destination and relays it through
//! the client, mirroring the Go TUN handler. TCP flows are spliced to
//! [`Client::tcp`] with `copy_bidirectional`; UDP uses per-source NAT (one
//! [`Client::udp`] session per app source endpoint, see the `session` module).
//! IPv4 and
//! IPv6 are both handled.
//!
//! Production loads this behind the FFI extension over the OS-provided fd. The
//! device is supplied by the caller as an [`AsyncDevice`] — this crate never
//! opens one and never names a fd, so it stays `unsafe`-free; the extension wraps
//! the `NetworkExtension` fd with `unsafe AsyncDevice::from_fd` (in `ffi-ext`) and
//! passes it in, along with the NE-assigned addresses via [`Config`]. The
//! `tun-bridge` dev binary instead opens a macOS utun and calls [`run`].
//!
//! [`spawn`] returns a [`Handle`] for live [`Stats`] and graceful shutdown;
//! [`run`] is the blocking convenience used by the dev harness.

mod count;
mod device;
mod session;
mod stack;
mod tcp;
mod udp;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context as _;
use anyhow::Result;
use hysteria::client::Client;
pub use stack::Config;
pub use stack::Limits;
use stack::StackHandle;
use stack::UDP_IDLE;
use tokio::io::copy_bidirectional;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tun_rs::AsyncDevice;

use crate::count::Counting;
use crate::session::RecvCtx;
use crate::session::Sessions;
use crate::stack::TcpFlow;
use crate::udp::UdpInbound;

/// How often idle UDP sessions are swept.
const GC_INTERVAL: Duration = Duration::from_secs(30);

/// Cumulative traffic and flow counters at the smoltcp↔hysteria seam. Each is an
/// independent `Arc` so tasks share exactly the counter they touch.
#[derive(Clone)]
struct Counters {
    /// Bytes app→server.
    tx: Arc<AtomicU64>,
    /// Bytes server→app.
    rx: Arc<AtomicU64>,
    /// TCP flows opened.
    tcp_flows: Arc<AtomicU64>,
    /// UDP sessions opened.
    udp_sessions: Arc<AtomicU64>,
    /// Flows that failed to open or relay.
    flow_errors: Arc<AtomicU64>,
}

impl Counters {
    fn new() -> Self {
        Self {
            tx: Arc::new(AtomicU64::new(0)),
            rx: Arc::new(AtomicU64::new(0)),
            tcp_flows: Arc::new(AtomicU64::new(0)),
            udp_sessions: Arc::new(AtomicU64::new(0)),
            flow_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    fn snapshot(&self) -> Stats {
        Stats {
            tx: self.tx.load(Ordering::Relaxed),
            rx: self.rx.load(Ordering::Relaxed),
            tcp_flows: self.tcp_flows.load(Ordering::Relaxed),
            udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            flow_errors: self.flow_errors.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of cumulative tunnel traffic, for the stats surface (PLAN §5).
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// Bytes sent app→server.
    pub tx: u64,
    /// Bytes received server→app.
    pub rx: u64,
    /// TCP flows opened since start.
    pub tcp_flows: u64,
    /// UDP sessions opened since start.
    pub udp_sessions: u64,
    /// Flows that failed to open or relay.
    pub flow_errors: u64,
}

/// A handle to a running tunnel: live stats and graceful shutdown.
pub struct Handle {
    join: tokio::task::JoinHandle<()>,
    shutdown: watch::Sender<bool>,
    counters: Counters,
}

impl Handle {
    /// A snapshot of current traffic counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.counters.snapshot()
    }

    /// Ask the tunnel to stop: the netstack task and every relay/session task
    /// wind down. Idempotent; [`join`](Self::join) then completes.
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Wait for the tunnel to finish (after a [`trigger_shutdown`](Self::trigger_shutdown),
    /// a device error, or the netstack ending) and return the final [`Stats`].
    /// Reading them here — after every relay/session task has drained — gives
    /// exact counts. Errors only if the task panicked.
    pub async fn join(self) -> Result<Stats> {
        let counters = self.counters;
        self.join.await.context("tunnel task")?;
        Ok(counters.snapshot())
    }
}

/// Start the netstack over `device`, relaying every accepted flow through
/// `client`. Returns a [`Handle`] for stats and shutdown.
#[must_use]
pub fn spawn(device: Arc<AsyncDevice>, client: Arc<Client>, config: Config) -> Handle {
    let counters = Counters::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let stack = stack::start(device, config, shutdown_rx.clone());
    let join = tokio::spawn(orchestrate(client, stack, counters.clone(), shutdown_rx));
    Handle {
        join,
        shutdown: shutdown_tx,
        counters,
    }
}

/// Run the netstack until the device errors or the netstack ends. The blocking
/// convenience used by the `tun-bridge` dev harness; production uses [`spawn`].
pub async fn run(device: Arc<AsyncDevice>, client: Arc<Client>, config: Config) -> Result<()> {
    spawn(device, client, config).join().await?;
    Ok(())
}

/// Drive accepted flows: splice TCP, NAT UDP, GC idle sessions, until a channel
/// closes (netstack ended) or shutdown is signalled. Then cancel every relay and
/// session task before returning.
async fn orchestrate(
    client: Arc<Client>,
    mut stack: StackHandle,
    counters: Counters,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions: Sessions<
        hysteria::client::udp::UdpConn<hysteria::client::transport::QuinnUdpIo>,
    > = Sessions::new();
    let recv_ctx = RecvCtx {
        udp_out: stack.udp_out.clone(),
        shutdown: shutdown.clone(),
        rx: Arc::clone(&counters.rx),
        sessions: Arc::clone(&counters.udp_sessions),
    };
    let mut relays: JoinSet<()> = JoinSet::new();
    let mut gc = tokio::time::interval(GC_INTERVAL);

    loop {
        tokio::select! {
            flow = stack.tcp_flows.recv() => {
                let Some(flow) = flow else { break };
                counters.tcp_flows.fetch_add(1, Ordering::Relaxed);
                let client = Arc::clone(&client);
                let tx = Arc::clone(&counters.tx);
                let rx = Arc::clone(&counters.rx);
                let errs = Arc::clone(&counters.flow_errors);
                relays.spawn(async move {
                    if relay_tcp(flow, client, tx, rx).await.is_err() {
                        errs.fetch_add(1, Ordering::Relaxed);
                    }
                });
            },
            inbound = stack.udp_in.recv() => {
                let Some(UdpInbound { src, dst, data }) = inbound else { break };
                let client = Arc::clone(&client);
                let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                let sent = sessions.forward(src, dst, &data, Instant::now(), &recv_ctx, move || {
                    client.udp().ok().map(Arc::new)
                });
                if sent {
                    counters.tx.fetch_add(len, Ordering::Relaxed);
                } else {
                    counters.flow_errors.fetch_add(1, Ordering::Relaxed);
                }
            },
            _ = gc.tick() => sessions.reap_idle(Instant::now(), UDP_IDLE),
            // Reap finished relays so the JoinSet doesn't grow unbounded.
            Some(_) = relays.join_next() => {},
            _ = shutdown.changed() => break,
        }
    }

    // Tear down: abort any in-flight relays (a relay blocked on the now-stopped
    // netstack would otherwise never wake) and drain them; `sessions`' Drop
    // aborts the per-session receive tasks.
    relays.abort_all();
    while relays.join_next().await.is_some() {}
}

/// Splice one app TCP flow to a Hysteria tunnel to its original destination,
/// counting bytes crossing the hysteria seam. This is Go's `tun.NewConnection`
/// (`app/internal/tun/server.go`): open `HyClient.TCP(reqAddr)` and copy both
/// ways — its two `io.Copy` goroutines collapse into one `copy_bidirectional`.
async fn relay_tcp(
    flow: TcpFlow,
    client: Arc<Client>,
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
) -> Result<()> {
    let tunnel = client
        .tcp(&flow.dst.to_string())
        .await
        .context("open tunnel")?;
    let mut tunnel = Counting::new(tunnel, tx, rx);
    let mut app = flow.stream;
    copy_bidirectional(&mut app, &mut tunnel)
        .await
        .context("relay TCP")?;
    Ok(())
}
