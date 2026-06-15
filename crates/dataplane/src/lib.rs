//! The dataplane: relay every flow the netstack accepts through the Hysteria 2
//! client.
//!
//! The userspace netstack lives below us in `netstack`: given a TUN
//! device it hands back accepted async TCP streams (each with its original
//! destination) and UDP datagrams. We relay those through the `hysteria` client,
//! owning the relay tasks and the per-source UDP NAT (the `session` module, generic
//! over its `Upstream`/`Downstream` seams so it carries no transport type). Packet
//! parsing, socket lifecycle, and flow detection all live in the netstack crate.
//!
//! The device is supplied by the caller as an [`AsyncDevice`] (the OS-provided fd
//! behind the FFI extension, or a utun in the `transport-tun` dev harness).
//! [`spawn`] returns a [`Handle`] for live [`Stats`] and graceful shutdown; [`run`]
//! is the blocking convenience used by the dev harness.

mod count;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context as _;
use anyhow::Result;
use hysteria::client::Client;
use netstack as socket;
use netstack::AsyncDevice;
use netstack::TcpStream;
use tokio::io::copy_bidirectional;
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;

use crate::count::Counting;
use crate::session::Downstream;
use crate::session::Outcome;
use crate::session::Sessions;

/// How often idle UDP sessions are swept.
const GC_INTERVAL: Duration = Duration::from_secs(30);
/// Idle UDP sessions are reaped after this long (mirrors the Go TUN handler's
/// UDP timeout).
const UDP_IDLE: Duration = Duration::from_mins(5);

/// The concrete Hysteria UDP session type the NAT map holds.
type Session = hysteria::client::udp::UdpConn<hysteria::client::transport::QuinnUdpIo>;

/// The dataplane's [`Downstream`]: queues each reply for the netstack's UDP writer
/// (via the socket crate's [`UdpSender`](socket::UdpSender)) and tallies received
/// bytes at the seam. This is where the NAT's caller-owned concerns — the reply
/// sender and the `rx` counter — live, keeping `session` metric-free.
#[derive(Clone)]
struct ReplyQueue {
    udp: socket::UdpSender,
    /// Bytes received from remotes (server→app), tallied as they arrive.
    rx: Arc<AtomicU64>,
}

impl Downstream for ReplyQueue {
    async fn deliver(&self, src: SocketAddr, from: SocketAddr, data: Vec<u8>) -> bool {
        self.rx.fetch_add(
            u64::try_from(data.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.udp.send(data, from, src).await
    }
}

/// Buffer/flow caps. The `*_buffer` values are channel depths bounding queued
/// packets/datagrams; the `max_*` values cap concurrent flows.
///
/// Caveat on TCP memory: `max_tcp_flows` caps live *relays* (and the hysteria-side
/// resources they hold), not the netstack's per-socket buffers. `netstack-smoltcp`
/// allocates a fixed per-connection buffer set on the first SYN, before our accept
/// loop sees the flow, and its accept backlog is unbounded — so a local app
/// spraying SYNs can transiently allocate beyond this cap until we drain and close
/// the excess. Bounding that needs an upstream knob (a bounded backlog /
/// configurable buffer size); acceptable on the current desktop/Android targets.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Stack↔TUN packet channel depth.
    pub stack_buffer: usize,
    /// UDP datagram channel depth.
    pub udp_buffer: usize,
    /// TCP accept-backlog channel depth.
    pub tcp_buffer: usize,
    /// Max concurrent TCP relays; further accepted flows are dropped (closed).
    pub max_tcp_flows: usize,
    /// Max concurrent UDP NAT sessions (one per app source endpoint).
    pub max_udp_sessions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            stack_buffer: 512,
            udp_buffer: 128,
            tcp_buffer: 128,
            max_tcp_flows: 256,
            max_udp_sessions: 256,
        }
    }
}

/// Netstack settings supplied by the front-end.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// TUN MTU.
    pub mtu: usize,
    /// Buffer/flow caps.
    pub limits: Limits,
}

impl Config {
    /// A config with default limits for the given MTU.
    #[must_use]
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu,
            limits: Limits::default(),
        }
    }
}

/// Cumulative traffic and flow counters at the seam, shared with the tasks.
#[derive(Clone)]
struct Counters {
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
    tcp_flows: Arc<AtomicU64>,
    udp_sessions: Arc<AtomicU64>,
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

/// A snapshot of cumulative tunnel traffic, for the model's stats surface.
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
    join: JoinHandle<()>,
    shutdown: watch::Sender<bool>,
    counters: Counters,
}

impl Handle {
    /// A snapshot of current traffic counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.counters.snapshot()
    }

    /// Ask the tunnel to stop: the netstack and every relay/session task wind
    /// down. Idempotent; [`join`](Self::join) then completes.
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Wait for the tunnel to finish and return the final [`Stats`] (read after
    /// every task has drained). Errors only if the orchestration task panicked.
    pub async fn join(self) -> Result<Stats> {
        let counters = self.counters;
        self.join.await.context("tunnel task")?;
        Ok(counters.snapshot())
    }
}

/// Start the netstack over `device`, relaying every accepted flow through
/// `client`. Returns a [`Handle`] for stats and shutdown. Errors if the netstack
/// cannot be built.
pub fn spawn(device: Arc<AsyncDevice>, client: Arc<Client>, config: Config) -> Result<Handle> {
    let counters = Counters::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Project the netstack subset of our config; the `max_*` caps stay here.
    let sockets = socket::build(
        device,
        socket::Config {
            mtu: config.mtu,
            stack_buffer: config.limits.stack_buffer,
            udp_buffer: config.limits.udp_buffer,
            tcp_buffer: config.limits.tcp_buffer,
        },
    )?;

    let join = tokio::spawn(orchestrate(
        sockets,
        client,
        counters.clone(),
        shutdown_rx,
        config,
    ));
    Ok(Handle {
        join,
        shutdown: shutdown_tx,
        counters,
    })
}

/// Spawn the netstack and await it to completion (the device erroring or the
/// netstack ending). A convenience for callers that don't need the [`Handle`];
/// callers that want live stats or graceful shutdown use [`spawn`].
pub async fn run(device: Arc<AsyncDevice>, client: Arc<Client>, config: Config) -> Result<()> {
    spawn(device, client, config)?.join().await?;
    Ok(())
}

/// Drive the dataplane: accept TCP flows and relay them, NAT UDP, and GC idle
/// sessions — until a netstack stream closes, an infra task ends, or shutdown is
/// signalled, then cancel every task.
async fn orchestrate(
    sockets: socket::Sockets,
    client: Arc<Client>,
    counters: Counters,
    mut shutdown: watch::Receiver<bool>,
    config: Config,
) {
    let socket::Sockets {
        mut tcp,
        mut udp_rx,
        udp_tx,
        mut infra,
    } = sockets;

    let replies = ReplyQueue {
        udp: udp_tx,
        rx: Arc::clone(&counters.rx),
    };
    let mut sessions: Sessions<Session, ReplyQueue> =
        Sessions::new(config.limits.max_udp_sessions, replies, shutdown.clone());
    let semaphore = Arc::new(Semaphore::new(config.limits.max_tcp_flows));

    // Per-flow TCP relays, in their own set so we can reap them.
    let mut relays: JoinSet<()> = JoinSet::new();

    let mut gc = tokio::time::interval(GC_INTERVAL);
    loop {
        tokio::select! {
            accepted = tcp.accept() => {
                let Some((app, dst)) = accepted else { break };
                counters.tcp_flows.fetch_add(1, Ordering::Relaxed);
                // Cap concurrency: at the limit, drop the flow (the netstack
                // closes it) rather than hold another per-socket buffer set.
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    drop(app);
                    continue;
                };
                let client = Arc::clone(&client);
                let tx = Arc::clone(&counters.tx);
                let rx = Arc::clone(&counters.rx);
                let errs = Arc::clone(&counters.flow_errors);
                relays.spawn(async move {
                    let _permit = permit;
                    if relay_tcp(app, dst, client, tx, rx).await.is_err() {
                        errs.fetch_add(1, Ordering::Relaxed);
                    }
                });
            },
            inbound = udp_rx.recv() => {
                let Some((data, src, dst)) = inbound else { break };
                let client = Arc::clone(&client);
                let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                match sessions.forward(src, dst, &data, Instant::now(), move || {
                    client.udp().ok().map(Arc::new)
                }) {
                    Outcome::Sent { opened } => {
                        counters.tx.fetch_add(len, Ordering::Relaxed);
                        if opened {
                            counters.udp_sessions.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Outcome::Dropped { opened } => {
                        counters.flow_errors.fetch_add(1, Ordering::Relaxed);
                        // A fresh session whose first send failed is still in the
                        // map, so count it like any other opened session.
                        if opened {
                            counters.udp_sessions.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            },
            _ = gc.tick() => sessions.reap_idle(Instant::now(), UDP_IDLE),
            Some(_) = relays.join_next() => {},
            // An infra task ending (the runner, either TUN pump, or the UDP
            // writer) means the data path is broken — e.g. the device errored —
            // so tear the whole tunnel down rather than stall silently.
            () = infra.failed() => break,
            _ = shutdown.changed() => break,
        }
    }

    // Cancel relays first (a relay blocked on the now-stopping netstack would
    // never wake otherwise), then the infrastructure tasks; `sessions`' Drop
    // aborts the per-session receive tasks.
    relays.abort_all();
    while relays.join_next().await.is_some() {}
    infra.shutdown().await;
}

/// Splice one accepted TCP flow to a Hysteria tunnel to its original destination,
/// counting bytes crossing the hysteria seam. Mirrors Go's `tun.NewConnection`.
async fn relay_tcp(
    mut app: TcpStream,
    dst: SocketAddr,
    client: Arc<Client>,
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
) -> Result<()> {
    let tunnel = client.tcp(&dst.to_string()).await.context("open tunnel")?;
    let mut tunnel = Counting::new(tunnel, tx, rx);
    copy_bidirectional(&mut app, &mut tunnel)
        .await
        .context("relay TCP")?;
    Ok(())
}
