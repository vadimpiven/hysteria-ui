//! Async `AsyncRead`/`AsyncWrite` view of one smoltcp TCP socket.
//!
//! The smoltcp socket is the *local* end of the app's connection (smoltcp acts
//! as the server the app dialed). So reads here yield bytes the app sent, and
//! writes deliver bytes back to the app — the relay copies between this and the
//! Hysteria stream. Readiness rides smoltcp's per-socket wakers; every buffer
//! change notifies the netstack task to re-poll (so it (n)acks and emits frames).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::sync::Notify;

use crate::stack::SharedRef;
use crate::stack::lock;

/// One proxied TCP flow: a smoltcp socket handle plus the shared netstack state.
pub(crate) struct TcpStream {
    shared: SharedRef,
    handle: SocketHandle,
    notify: Arc<Notify>,
    /// Liveness token: the netstack task holds a `Weak` to it and only removes
    /// the socket once this stream drops, keeping `handle` valid for every access
    /// here. smoltcp's `SocketSet` panics on a removed handle and recycles slots,
    /// which would otherwise cross-wire two flows.
    _alive: Arc<()>,
}

impl TcpStream {
    pub(crate) fn new(
        shared: SharedRef,
        handle: SocketHandle,
        notify: Arc<Notify>,
        alive: Arc<()>,
    ) -> Self {
        Self {
            shared,
            handle,
            notify,
            _alive: alive,
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A zero-capacity read isn't EOF; the caller just asked for nothing.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut shared = lock(&self.shared);
        let socket = shared.sockets.get_mut::<tcp::Socket<'_>>(self.handle);
        if socket.can_recv() {
            let dst = buf.initialize_unfilled();
            match socket.recv_slice(dst) {
                Ok(n) => {
                    buf.advance(n);
                    drop(shared);
                    self.notify.notify_one();
                    Poll::Ready(Ok(()))
                },
                Err(_) => Poll::Ready(Ok(())), // closed ⇒ EOF
            }
        } else if socket.may_recv() {
            // Still open, just no data yet: wake us when some arrives.
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        } else {
            // Peer closed and the buffer is drained ⇒ EOF (zero bytes filled).
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // A zero-length write isn't a stall; the `AsyncWrite` contract is to
        // report it written immediately (`send_slice(&[])` returns `Ok(0)`,
        // which the readiness logic below would misread as a full buffer).
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut shared = lock(&self.shared);
        let socket = shared.sockets.get_mut::<tcp::Socket<'_>>(self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.can_send() {
            match socket.send_slice(buf) {
                Ok(0) => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                },
                Ok(n) => {
                    drop(shared);
                    self.notify.notify_one();
                    Poll::Ready(Ok(n))
                },
                Err(e) => Poll::Ready(Err(io::Error::other(e))),
            }
        } else {
            socket.register_send_waker(cx.waker());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // smoltcp drains its tx buffer on the next poll; nudge it.
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut shared = lock(&self.shared);
        shared
            .sockets
            .get_mut::<tcp::Socket<'_>>(self.handle)
            .close();
        drop(shared);
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Begin a graceful close; the netstack task reaps the socket once it
        // reaches the Closed state.
        {
            let mut shared = lock(&self.shared);
            shared
                .sockets
                .get_mut::<tcp::Socket<'_>>(self.handle)
                .close();
        }
        self.notify.notify_one();
    }
}
