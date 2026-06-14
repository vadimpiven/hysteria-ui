//! Userspace TUN netstack that drives the Hysteria 2 client.
//!
//! Bridges a TUN device (raw IP packets) to the `hysteria` client. The userspace
//! netstack is `netstack-smoltcp`: it accepts each flow from the TUN's packets
//! and hands back an async TCP stream (with the original destination) or UDP
//! datagrams, which we relay through the client. We own the relay tasks and the
//! per-source UDP NAT (the `session` module, generic over its `Upstream`/
//! `Downstream` seams so it carries no tunnel type); packet parsing, socket
//! lifecycle, and flow detection live in the netstack crate.
//!
//! The device is supplied by the caller as an [`AsyncDevice`] (the OS-provided fd
//! behind the FFI extension, or a utun in the `tun-bridge` dev harness). [`spawn`]
//! returns a [`Handle`] for live [`Stats`] and graceful shutdown; [`run`] is the
//! blocking convenience used by the dev harness.

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
use anyhow::anyhow;
use futures::SinkExt as _;
use futures::StreamExt as _;
use hysteria::client::Client;
use netstack_smoltcp::Runner;
use netstack_smoltcp::Stack;
use netstack_smoltcp::StackBuilder;
use netstack_smoltcp::TcpListener;
use netstack_smoltcp::TcpStream;
use netstack_smoltcp::UdpSocket;
use tokio::io::copy_bidirectional;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use tun_rs::AsyncDevice;

use crate::count::Counting;
use crate::session::Downstream;
use crate::session::Outcome;
use crate::session::Sessions;

/// How often idle UDP sessions are swept.
const GC_INTERVAL: Duration = Duration::from_secs(30);
/// Idle UDP sessions are reaped after this long (mirrors the Go TUN handler's
/// UDP timeout).
const UDP_IDLE: Duration = Duration::from_mins(5);
/// Reply channel depth between the session tasks and the UDP writer.
const REPLY_CHANNEL: usize = 256;

/// The concrete Hysteria UDP session type the NAT map holds.
type Session = hysteria::client::udp::UdpConn<hysteria::client::transport::QuinnUdpIo>;

/// A reply datagram from a remote back to the app, queued for the UDP writer.
/// `src` is the app endpoint to deliver to; `from` is the remote it came from,
/// sent as the reply's source so the app sees an answer from where it asked.
pub(crate) struct UdpReply {
    pub(crate) src: SocketAddr,
    pub(crate) from: SocketAddr,
    pub(crate) data: Vec<u8>,
}

/// The tunnel's [`Downstream`]: queues each reply for the UDP writer and tallies
/// received bytes at the seam. This is where the NAT's caller-owned concerns —
/// the reply channel and the `rx` counter — live, keeping `session` metric-free.
#[derive(Clone)]
struct ReplyQueue {
    reply_tx: mpsc::Sender<UdpReply>,
    /// Bytes received from remotes (server→app), tallied as they arrive.
    rx: Arc<AtomicU64>,
}

impl Downstream for ReplyQueue {
    async fn deliver(&self, src: SocketAddr, from: SocketAddr, data: Vec<u8>) -> bool {
        self.rx.fetch_add(
            u64::try_from(data.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.reply_tx
            .send(UdpReply { src, from, data })
            .await
            .is_ok()
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

    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(config.mtu)
        .stack_buffer_size(config.limits.stack_buffer)
        .udp_buffer_size(config.limits.udp_buffer)
        .tcp_buffer_size(config.limits.tcp_buffer)
        .build()
        .context("build netstack")?;
    // All present because TCP/UDP/ICMP are enabled above; avoid `unwrap`.
    let runner = runner.ok_or_else(|| anyhow!("netstack runner missing"))?;
    let udp_socket = udp_socket.ok_or_else(|| anyhow!("netstack UDP socket missing"))?;
    let tcp_listener = tcp_listener.ok_or_else(|| anyhow!("netstack TCP listener missing"))?;

    let netstack = Netstack {
        device,
        client,
        stack,
        runner,
        udp_socket,
        tcp_listener,
        counters: counters.clone(),
        shutdown: shutdown_rx,
        config,
    };
    let join = tokio::spawn(orchestrate(netstack));
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

/// Everything the orchestration task owns.
struct Netstack {
    device: Arc<AsyncDevice>,
    client: Arc<Client>,
    stack: Stack,
    runner: Runner,
    udp_socket: UdpSocket,
    tcp_listener: TcpListener,
    counters: Counters,
    shutdown: watch::Receiver<bool>,
    config: Config,
}

/// Drive the netstack: pump packets to/from the TUN, accept TCP flows and relay
/// them, NAT UDP, and GC idle sessions — until a stream closes or shutdown is
/// signalled, then cancel every task.
#[expect(
    clippy::too_many_lines,
    reason = "netstack setup plus the select loop; the split() halves have \
              unnameable types, so the loop can't be extracted across a fn boundary"
)]
async fn orchestrate(ns: Netstack) {
    let Netstack {
        device,
        client,
        stack,
        runner,
        udp_socket,
        mut tcp_listener,
        counters,
        mut shutdown,
        config,
    } = ns;

    let (mut sink, mut stream) = stack.split();
    let (mut udp_rd, mut udp_wr) = udp_socket.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(REPLY_CHANNEL);
    let replies = ReplyQueue {
        reply_tx,
        rx: Arc::clone(&counters.rx),
    };
    let mut sessions: Sessions<Session, ReplyQueue> =
        Sessions::new(config.limits.max_udp_sessions, replies, shutdown.clone());
    let semaphore = Arc::new(Semaphore::new(config.limits.max_tcp_flows));

    // Infrastructure tasks (the netstack runner + the TUN<->stack pumps + the UDP
    // writer); per-flow TCP relays go in their own set so we can reap them.
    let mut infra: JoinSet<()> = JoinSet::new();
    let mut relays: JoinSet<()> = JoinSet::new();

    infra.spawn(async move {
        let _ = runner.await;
    });

    // TUN → stack: read IP packets off the device and feed the netstack.
    {
        let device = Arc::clone(&device);
        // Floor the read buffer at a standard frame so a small configured MTU
        // can't truncate an inbound packet.
        let mtu = config.mtu.max(1500);
        infra.spawn(async move {
            let mut buf = vec![0u8; mtu];
            loop {
                let Ok(n) = device.recv(&mut buf).await else {
                    break;
                };
                let Some(slice) = buf.get(..n) else {
                    continue;
                };
                if sink.send(slice.to_vec()).await.is_err() {
                    break;
                }
            }
        });
    }

    // stack → TUN: write the netstack's emitted packets back out.
    {
        let device = Arc::clone(&device);
        infra.spawn(async move {
            while let Some(pkt) = stream.next().await {
                if let Ok(pkt) = pkt
                    && device.send(&pkt).await.is_err()
                {
                    break;
                }
            }
        });
    }

    // UDP writer: the single owner of the write half, fed reply datagrams by the
    // per-session tasks. Sends `(data, from, src)` so the reply's source is the
    // remote the app addressed.
    infra.spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            // Spoofing the source needs `from` and `src` in the same address
            // family; a mismatched pair (not reachable in practice — a session's
            // replies share the app's family) would make the netstack reject the
            // send and, via `infra.join_next`, tear the tunnel down. Skip it.
            if reply.from.is_ipv4() != reply.src.is_ipv4() {
                continue;
            }
            if udp_wr
                .send((reply.data, reply.from, reply.src))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut gc = tokio::time::interval(GC_INTERVAL);
    loop {
        tokio::select! {
            accepted = tcp_listener.next() => {
                let Some((app, _local, remote)) = accepted else { break };
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
                    if relay_tcp(app, remote, client, tx, rx).await.is_err() {
                        errs.fetch_add(1, Ordering::Relaxed);
                    }
                });
            },
            inbound = udp_rd.next() => {
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
                    Outcome::Dropped => {
                        counters.flow_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            },
            _ = gc.tick() => sessions.reap_idle(Instant::now(), UDP_IDLE),
            Some(_) = relays.join_next() => {},
            // An infra task ending (the runner, either TUN pump, or the UDP
            // writer) means the data path is broken — e.g. the device errored —
            // so tear the whole tunnel down rather than stall silently.
            Some(_) = infra.join_next() => break,
            _ = shutdown.changed() => break,
        }
    }

    // Cancel relays first (a relay blocked on the now-stopping netstack would
    // never wake otherwise), then the infrastructure tasks; `sessions`' Drop
    // aborts the per-session receive tasks.
    relays.abort_all();
    while relays.join_next().await.is_some() {}
    infra.abort_all();
    while infra.join_next().await.is_some() {}
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
