//! A socket-style API over a userspace smoltcp netstack driven by a TUN device.
//!
//! Wraps `netstack-smoltcp` (which itself wraps smoltcp): given a TUN
//! [`AsyncDevice`], [`build`] stands up the stack, spawns the netstack runner and
//! the two TUN<->stack packet pumps plus a single-owner UDP writer, and hands back
//! socket-style halves — a [`TcpAcceptor`], a [`UdpReceiver`], a cloneable
//! [`UdpSender`], and the [`Infra`] task set. Packet parsing, socket lifecycle, and
//! flow detection all live below this seam; callers deal only in nameable types
//! ([`TcpStream`], `Vec<u8>`, `SocketAddr`), with no knowledge of what they relay
//! the flows through.
//!
//! The halves are returned as separate owners (not one object) on purpose: the
//! accept/recv/failed methods each take `&mut self`, so a caller can drive all
//! three from distinct arms of one `tokio::select!` without overlapping borrows.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use futures::SinkExt as _;
use futures::StreamExt as _;
use netstack_smoltcp::StackBuilder;
use netstack_smoltcp::TcpListener;
pub use netstack_smoltcp::TcpStream;
use netstack_smoltcp::udp;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
pub use tun_rs::AsyncDevice;

/// Reply channel depth between the caller's [`UdpSender`]s and the UDP writer.
const REPLY_CHANNEL: usize = 256;

/// A reply datagram queued for the UDP writer, in the netstack's
/// `(payload, local, remote)` tuple shape. We send `(data, from, src)` so the
/// emitted packet is sourced at `from` (the remote the app addressed) and
/// destined for `src` (the app), making the app see an answer from where it asked.
type Reply = (Vec<u8>, SocketAddr, SocketAddr);

/// Netstack build settings. Only the knobs the stack itself needs; the caller's
/// flow caps (max relays / NAT sessions) stay above this seam.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// TUN MTU.
    pub mtu: usize,
    /// Stack↔TUN packet channel depth.
    pub stack_buffer: usize,
    /// UDP datagram channel depth.
    pub udp_buffer: usize,
    /// TCP accept-backlog channel depth.
    pub tcp_buffer: usize,
}

/// Build the smoltcp stack over `device`, spawning the netstack runner, both
/// TUN<->stack pumps, and the UDP writer. Returns the socket-style halves the
/// caller drives. Errors if the netstack cannot be built.
pub fn build(device: Arc<AsyncDevice>, config: Config) -> Result<Sockets> {
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(config.mtu)
        .stack_buffer_size(config.stack_buffer)
        .udp_buffer_size(config.udp_buffer)
        .tcp_buffer_size(config.tcp_buffer)
        .build()
        .context("build netstack")?;
    // All present because TCP/UDP/ICMP are enabled above; avoid `unwrap`.
    let runner = runner.ok_or_else(|| anyhow!("netstack runner missing"))?;
    let udp_socket = udp_socket.ok_or_else(|| anyhow!("netstack UDP socket missing"))?;
    let tcp_listener = tcp_listener.ok_or_else(|| anyhow!("netstack TCP listener missing"))?;

    let (mut sink, mut stream) = stack.split();
    let (udp_rd, mut udp_wr) = udp_socket.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<Reply>(REPLY_CHANNEL);

    // Infrastructure tasks: the netstack runner, the two TUN<->stack pumps, and
    // the UDP writer. Owned by `Infra`; any one ending means the data path broke.
    let mut infra: JoinSet<()> = JoinSet::new();

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

    // stack → TUN: write the netstack's emitted packets back out. This is the
    // last user of `device`, so move the original `Arc` in rather than clone it.
    infra.spawn(async move {
        while let Some(pkt) = stream.next().await {
            if let Ok(pkt) = pkt
                && device.send(&pkt).await.is_err()
            {
                break;
            }
        }
    });

    // UDP writer: the single owner of the write half, fed reply datagrams by the
    // caller's per-session [`UdpSender`]s. The tuple is `(data, from, src)` so the
    // reply's source is the remote the app addressed.
    infra.spawn(async move {
        while let Some((data, from, src)) = reply_rx.recv().await {
            // Spoofing the source needs `from` and `src` in the same address
            // family; a mismatched pair (not reachable in practice — a session's
            // replies share the app's family) would make the netstack reject the
            // send and tear the data path down. Skip it.
            if from.is_ipv4() != src.is_ipv4() {
                continue;
            }
            if udp_wr.send((data, from, src)).await.is_err() {
                break;
            }
        }
    });

    Ok(Sockets {
        tcp: TcpAcceptor(tcp_listener),
        udp_rx: UdpReceiver(udp_rd),
        udp_tx: UdpSender(reply_tx),
        infra: Infra(infra),
    })
}

/// The socket-style halves of a built netstack. Destructure into the four owned
/// fields so each can be driven from a distinct `select!` arm without the three
/// `&mut self` methods overlapping their borrows.
pub struct Sockets {
    /// Accepts TCP flows, each with its original destination.
    pub tcp: TcpAcceptor,
    /// Receives UDP datagrams the app sent into the netstack.
    pub udp_rx: UdpReceiver,
    /// Queues reply datagrams back toward the app (cloneable per session).
    pub udp_tx: UdpSender,
    /// The netstack's infrastructure tasks.
    pub infra: Infra,
}

/// Accepts TCP flows from the netstack, each carrying its original destination.
pub struct TcpAcceptor(TcpListener);

impl TcpAcceptor {
    /// The next accepted flow as `(stream, dst)`, where `dst` is the destination
    /// the app addressed. `None` once the netstack closes.
    pub async fn accept(&mut self) -> Option<(TcpStream, SocketAddr)> {
        let (stream, _local, remote) = self.0.next().await?;
        Some((stream, remote))
    }
}

/// Receives the UDP datagrams the app sent into the netstack.
pub struct UdpReceiver(udp::ReadHalf);

impl UdpReceiver {
    /// The next datagram as `(data, src, dst)`: payload, the app source endpoint
    /// it came from, and the destination it addressed. `None` once the netstack
    /// closes.
    pub async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.0.next().await
    }
}

/// Queues reply datagrams for the UDP writer. Cloneable: one clone per UDP
/// session, all feeding the single write half.
#[derive(Clone)]
pub struct UdpSender(mpsc::Sender<Reply>);

impl UdpSender {
    /// Queue one reply: payload `data` from remote `from`, addressed back to app
    /// source `src`. Returns `false` if the writer is gone.
    pub async fn send(&self, data: Vec<u8>, from: SocketAddr, src: SocketAddr) -> bool {
        self.0.send((data, from, src)).await.is_ok()
    }
}

/// The netstack's infrastructure tasks (runner + both TUN pumps + UDP writer).
pub struct Infra(JoinSet<()>);

impl Infra {
    /// Resolves when any infrastructure task ends — the data path has broken (the
    /// device errored, a stream closed, or a task panicked). Cancel-safe, so it
    /// can sit in a `select!` arm; the caller tears the rest down in response.
    pub async fn failed(&mut self) {
        let _ = self.0.join_next().await;
    }

    /// Abort every infrastructure task and wait for them to drain.
    pub async fn shutdown(mut self) {
        self.0.abort_all();
        while self.0.join_next().await.is_some() {}
    }
}
