//! UDP session manager.
//!
//! Port of `core/client/udp.go`. The Go implementation uses a goroutine plus a
//! `sync.RWMutex` and channels; the Rust port uses a Tokio task, a
//! `std::sync::Mutex` over the session table (never held across an `.await`), and
//! a `tokio::sync::mpsc` channel per session.
//!
//! Ownership differs from Go's shared `*udpConn`: the manager keeps only the
//! sending half of each session's channel (for `feed`), and the consumer holds a
//! [`UdpConn`] with the receiving half plus its `Defragger`. "Closing" a
//! session is simply dropping the manager's sender, which makes the consumer's
//! [`UdpConn::receive`] observe EOF — the direct analogue of Go closing the
//! channel. The [`UdpConn`] methods take `&self` (interior mutability) so a
//! consumer can `receive`, `send`, and `close` concurrently from different tasks,
//! mirroring Go's any-goroutine access.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use rand::Rng as _;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::errors::ClosedError;
use crate::internal::frag::Defragger;
use crate::internal::frag::frag_udp_message;
use crate::internal::protocol::MAX_UDP_SIZE;
use crate::internal::protocol::UdpMessage;

const UDP_MESSAGE_CHAN_SIZE: usize = 1024;

/// Lock a `std::sync::Mutex`, recovering the guard even if a previous holder
/// panicked (poison). Avoids `.unwrap()`/`.expect()`, which the crate denies.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Why a datagram could not be sent.
#[derive(Debug)]
pub enum SendError {
    /// The datagram exceeded the path's maximum; the carried payload size drives
    /// fragmentation (Go's `quic.DatagramTooLargeError.MaxDatagramPayloadSize`).
    TooLarge { max_payload_size: usize },
    /// Any other send failure.
    Io(io::Error),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_payload_size } => {
                write!(f, "datagram too large (max payload {max_payload_size})")
            },
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::TooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for SendError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// The transport the session manager drives: receive the next inbound UDP
/// message, and send one (serializing into the provided scratch buffer).
///
/// The real implementation wraps a Quinn connection's datagrams; tests provide a
/// fake. `send_message` reports [`SendError::TooLarge`] when the datagram does
/// not fit, which triggers fragmentation.
pub trait UdpIo: Send + Sync + 'static {
    fn receive_message(&self) -> impl Future<Output = io::Result<UdpMessage>> + Send;
    fn send_message(&self, buf: &mut [u8], msg: &UdpMessage) -> Result<(), SendError>;
}

/// Per-session receive state, owned by the consumer side.
struct RecvState {
    receiver: mpsc::Receiver<UdpMessage>,
    defragger: Defragger,
}

/// A single UDP session. Created by [`UdpSessionManager::new_udp`].
pub struct UdpConn<I: UdpIo> {
    id: u32,
    recv: AsyncMutex<RecvState>,
    // Shared scratch buffer for serialization (Go's per-conn `SendBuf`).
    send_buf: Mutex<Vec<u8>>,
    io: Arc<I>,
    shared: Arc<Shared>,
}

impl<I: UdpIo> UdpConn<I> {
    /// Receive the next fully reassembled datagram as `(data, addr)`. Returns an
    /// `UnexpectedEof` error once the session (or the manager) is closed — the
    /// equivalent of Go returning `io.EOF`.
    pub async fn receive(&self) -> io::Result<(Vec<u8>, String)> {
        let mut state = self.recv.lock().await;
        loop {
            let Some(msg) = state.receiver.recv().await else {
                // Closed.
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            if let Some(assembled) = state.defragger.feed(msg) {
                return Ok((assembled.data, assembled.addr));
            }
            // Incomplete message, wait for more.
        }
    }

    /// Send `data` to `addr`. Tries unfragmented first; if the transport reports
    /// the datagram is too large, fragments under a fresh random packet ID.
    ///
    /// Not safe to call concurrently with itself (it reuses a shared scratch
    /// buffer), matching the Go original.
    pub fn send(&self, data: &[u8], addr: &str) -> Result<(), SendError> {
        let mut buf = lock(&self.send_buf);
        let mut msg = UdpMessage {
            session_id: self.id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_string(),
            data: data.to_vec(),
        };
        match self.io.send_message(buf.as_mut_slice(), &msg) {
            Err(SendError::TooLarge { max_payload_size }) => {
                // Message too large, try fragmentation.
                msg.packet_id = random_packet_id();
                for frag in frag_udp_message(&msg, max_payload_size) {
                    self.io.send_message(buf.as_mut_slice(), &frag)?;
                }
                Ok(())
            },
            other => other,
        }
    }

    /// Close this session. Idempotent. Drops the manager's sender, so a pending
    /// or future [`receive`](Self::receive) observes EOF.
    pub fn close(&self) {
        lock(&self.shared.sessions).map.remove(&self.id);
    }
}

/// A random non-zero packet ID for a fragmented message
/// (`uint16(rand.Intn(0xFFFF)) + 1`).
fn random_packet_id() -> u16 {
    rand::rng().random_range(1..=u16::MAX)
}

/// The session table, shared between the manager, its run task, and the
/// consumer-held [`UdpConn`]s (for close).
struct Shared {
    sessions: Mutex<Sessions>,
}

struct Sessions {
    map: HashMap<u32, mpsc::Sender<UdpMessage>>,
    next_id: u32,
    closed: bool,
}

/// Routes inbound UDP messages from a [`UdpIo`] to per-session channels and
/// hands out [`UdpConn`]s. Stops its background task on drop.
pub struct UdpSessionManager<I: UdpIo> {
    shared: Arc<Shared>,
    io: Arc<I>,
    run_task: JoinHandle<()>,
}

impl<I: UdpIo> UdpSessionManager<I> {
    /// Start a manager over `io`. Must be called within a Tokio runtime; it
    /// spawns a task that pumps inbound messages until `io` errors.
    #[must_use]
    pub fn new(io: Arc<I>) -> Self {
        let shared = Arc::new(Shared {
            sessions: Mutex::new(Sessions {
                map: HashMap::new(),
                next_id: 1,
                closed: false,
            }),
        });
        let run_task = tokio::spawn(run(Arc::clone(&shared), Arc::clone(&io)));
        Self {
            shared,
            io,
            run_task,
        }
    }

    /// Create a new UDP session, or fail with [`ClosedError`] once the manager
    /// has shut down.
    pub fn new_udp(&self) -> Result<UdpConn<I>, ClosedError> {
        let mut sessions = lock(&self.shared.sessions);
        if sessions.closed {
            return Err(ClosedError::default());
        }
        let id = sessions.next_id;
        sessions.next_id = sessions.next_id.wrapping_add(1);
        let (sender, receiver) = mpsc::channel(UDP_MESSAGE_CHAN_SIZE);
        sessions.map.insert(id, sender);
        Ok(UdpConn {
            id,
            recv: AsyncMutex::new(RecvState {
                receiver,
                defragger: Defragger::default(),
            }),
            send_buf: Mutex::new(vec![0u8; MAX_UDP_SIZE]),
            io: Arc::clone(&self.io),
            shared: Arc::clone(&self.shared),
        })
    }

    /// Number of live sessions.
    #[must_use]
    pub fn count(&self) -> usize {
        lock(&self.shared.sessions).map.len()
    }
}

impl<I: UdpIo> Drop for UdpSessionManager<I> {
    fn drop(&mut self) {
        self.run_task.abort();
    }
}

/// The background pump: deliver inbound messages until the transport errors,
/// then tear down every session (Go's `run` + `closeCleanup`).
async fn run<I: UdpIo>(shared: Arc<Shared>, io: Arc<I>) {
    while let Ok(msg) = io.receive_message().await {
        feed(&shared, msg);
    }
    // Cleanup: dropping every sender makes consumers observe EOF, then refuse
    // new sessions.
    let mut sessions = lock(&shared.sessions);
    sessions.map.clear();
    sessions.closed = true;
}

/// Route one inbound message to its session, dropping it if the session is
/// unknown or its channel is full (Go's `feed`).
fn feed(shared: &Shared, msg: UdpMessage) {
    let sessions = lock(&shared.sessions);
    if let Some(sender) = sessions.map.get(&msg.session_id) {
        // Channel full ⇒ drop the message, like the Go `default:` branch.
        let _ = sender.try_send(msg);
    }
    // Unknown session ⇒ ignore.
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use anyhow::Result;
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    use super::*;

    // Aliased so the spawned-receive helper's signature stays under clippy's
    // `type_complexity` threshold.
    type ReceiveResult = io::Result<(Vec<u8>, String)>;

    /// Hand-rolled stand-in for the mockery-generated mock in `udp_test.go`:
    /// `receive_message` drains a channel (a closed channel ⇒ error, as the Go
    /// mock returns on `nil`), and `send_message` records the message.
    struct FakeIo {
        rx: AsyncMutex<mpsc::Receiver<UdpMessage>>,
        sent: Mutex<Vec<UdpMessage>>,
    }

    impl FakeIo {
        fn new(rx: mpsc::Receiver<UdpMessage>) -> Self {
            Self {
                rx: AsyncMutex::new(rx),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<UdpMessage> {
            lock(&self.sent).clone()
        }
    }

    impl UdpIo for FakeIo {
        async fn receive_message(&self) -> io::Result<UdpMessage> {
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn send_message(&self, _buf: &mut [u8], msg: &UdpMessage) -> Result<(), SendError> {
            lock(&self.sent).push(msg.clone());
            Ok(())
        }
    }

    fn message(session_id: u32, addr: &str, data: &[u8]) -> UdpMessage {
        UdpMessage {
            session_id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.into(),
            data: data.to_vec(),
        }
    }

    /// Await a spawned `receive` and assert it ended in EOF.
    async fn assert_receive_eof(handle: JoinHandle<ReceiveResult>, what: &str) -> Result<()> {
        let result = handle.await.with_context(|| format!("join {what}"))?;
        match result {
            Ok(_) => Err(anyhow!("{what}: receive should have returned EOF")),
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{what}: EOF kind");
                Ok(())
            },
        }
    }

    // Port of TestUDPSessionManager.
    #[tokio::test]
    async fn udp_session_manager() -> Result<()> {
        let (tx, rx) = mpsc::channel::<UdpMessage>(4);
        let io = Arc::new(FakeIo::new(rx));
        let sm = UdpSessionManager::new(Arc::clone(&io));

        // Two sessions get sequential IDs (1, 2).
        let conn1 = Arc::new(sm.new_udp().context("new_udp 1")?);
        let conn2 = Arc::new(sm.new_udp().context("new_udp 2")?);

        // Sending routes through the IO with the right session IDs.
        let msg1 = message(1, "random.site.com:9000", b"hello friend");
        conn1
            .send(&msg1.data, &msg1.addr)
            .map_err(|e| anyhow!("send 1: {e}"))?;
        let msg2 = message(2, "another.site.org:8000", b"mr robot");
        conn2
            .send(&msg2.data, &msg2.addr)
            .map_err(|e| anyhow!("send 2: {e}"))?;
        assert_eq!(
            io.sent(),
            vec![msg1.clone(), msg2.clone()],
            "both messages sent"
        );

        // Inbound messages are routed back to the matching session.
        let resp1 = message(1, &msg1.addr, b"goodbye captain price");
        tx.send(resp1.clone()).await.context("push resp1")?;
        let (data, addr) = conn1.receive().await.context("receive 1")?;
        assert_eq!(data, resp1.data, "conn1 data");
        assert_eq!(addr, resp1.addr, "conn1 addr");

        let resp2 = message(2, &msg2.addr, b"white rose");
        tx.send(resp2.clone()).await.context("push resp2")?;
        let (data, addr) = conn2.receive().await.context("receive 2")?;
        assert_eq!(data, resp2.data, "conn2 data");
        assert_eq!(addr, resp2.addr, "conn2 addr");

        // A bogus session ID is ignored (must not panic).
        let resp3 = message(55, "burgerking.com:27017", b"impossible whopper");
        tx.send(resp3).await.context("push resp3")?;

        // Closing a session unblocks its Receive with EOF.
        let pending1 = tokio::spawn({
            let conn1 = Arc::clone(&conn1);
            async move { conn1.receive().await }
        });
        conn1.close();
        assert_receive_eof(pending1, "after close").await?;

        // Closing the IO unblocks Receive and blocks new session creation.
        let pending2 = tokio::spawn({
            let conn2 = Arc::clone(&conn2);
            async move { conn2.receive().await }
        });
        drop(tx); // close IO
        assert_receive_eof(pending2, "after IO close").await?;
        assert!(sm.new_udp().is_err(), "new_udp after close should fail");

        assert_eq!(sm.count(), 0, "session count should be 0");
        Ok(())
    }
}
