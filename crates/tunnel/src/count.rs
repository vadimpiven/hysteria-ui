//! A byte-counting `AsyncRead`/`AsyncWrite` wrapper.
//!
//! Wraps the Hysteria side of a relay so the netstack reports live traffic at the
//! smoltcp↔hysteria seam. Reads add to `rx` (server→app bytes); writes add to
//! `tx` (app→server bytes). Counting only the hysteria side — never the smoltcp
//! side too — keeps each byte counted exactly once.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

/// Wraps a stream, tallying bytes read into `rx` and bytes written into `tx`.
pub(crate) struct Counting<S> {
    inner: S,
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
}

impl<S> Counting<S> {
    pub(crate) fn new(inner: S, tx: Arc<AtomicU64>, rx: Arc<AtomicU64>) -> Self {
        Self { inner, tx, rx }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let read = buf.filled().len().saturating_sub(before);
            self.rx
                .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = res {
            self.tx.fetch_add(
                u64::try_from(written).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[tokio::test]
    async fn counts_reads_and_writes_once() -> Result<()> {
        let tx = Arc::new(AtomicU64::new(0));
        let rx = Arc::new(AtomicU64::new(0));
        // A duplex: we write into `near`, read what the far end sends back.
        let (near, mut far) = tokio::io::duplex(64);
        let mut counted = Counting::new(near, Arc::clone(&tx), Arc::clone(&rx));

        counted.write_all(b"hello").await?;
        counted.flush().await?;
        assert_eq!(tx.load(Ordering::Relaxed), 5, "tx counts written bytes");

        far.write_all(b"worldly").await?;
        let mut buf = [0u8; 7];
        counted.read_exact(&mut buf).await?;
        assert_eq!(rx.load(Ordering::Relaxed), 7, "rx counts read bytes");
        Ok(())
    }
}
