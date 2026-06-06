//! A quinn `AsyncUdpSocket` that applies Salamander obfuscation per datagram.
//!
//! Port of the `extras/obfs` packet-conn wrapper onto quinn's socket
//! abstraction. Outbound datagrams are obfuscated before hitting the wire;
//! inbound datagrams are deobfuscated in place. GSO/GRO are disabled (one
//! datagram per operation) since obfuscation is per-packet.

use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use quinn::AsyncUdpSocket;
use quinn::UdpPoller;
use quinn::udp::RecvMeta;
use quinn::udp::Transmit;

use crate::internal::obfs::SalamanderObfuscator;

/// Scratch size for a datagram plus the 8-byte salt (Go's `udpBufferSize`).
/// quinn's MTU-discovery upper bound defaults to 1452 bytes, so an obfuscated
/// packet stays well under 2 KiB even with path-MTU discovery enabled.
const UDP_BUFFER_SIZE: usize = 2048;

/// Wraps an inner [`AsyncUdpSocket`], obfuscating every datagram.
pub struct ObfsUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: SalamanderObfuscator,
}

impl ObfsUdpSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, obfs: SalamanderObfuscator) -> Self {
        Self { inner, obfs }
    }
}

impl fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the obfuscator (it holds the PSK).
        f.debug_struct("ObfsUdpSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut buf = [0u8; UDP_BUFFER_SIZE];
        let n = self.obfs.obfuscate(transmit.contents, &mut buf);
        if n == 0 {
            // Larger than our scratch buffer: cannot obfuscate, drop silently.
            return Ok(());
        }
        let obfuscated = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf[..n],
            // GSO disabled: exactly one datagram per transmit.
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&obfuscated)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.inner.poll_recv(cx, bufs, meta);
        let Poll::Ready(Ok(count)) = result else {
            return result;
        };
        let mut scratch = [0u8; UDP_BUFFER_SIZE];
        for i in 0..count {
            let len = meta[i].len;
            let out_len = self.obfs.deobfuscate(&bufs[i][..len], &mut scratch);
            if out_len == 0 {
                // Not a valid obfuscated packet: present it as empty so quinn
                // discards it rather than misparsing the ciphertext.
                meta[i].len = 0;
                meta[i].stride = 0;
                continue;
            }
            bufs[i][..out_len].copy_from_slice(&scratch[..out_len]);
            meta[i].len = out_len;
            meta[i].stride = out_len;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
