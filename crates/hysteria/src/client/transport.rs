//! The Hysteria 2 client connection. Port of `core/client/client.go`.
//!
//! Flow: dial QUIC (TLS 1.3 + cert pinning, ALPN `h3`), run the HTTP/3 auth
//! handshake (`POST https://hysteria/auth`), then use the *same* QUIC connection
//! raw — bidi streams for the TCP relay, datagrams for the UDP relay — exactly as
//! the Go client does.
//!
//! Differences from Go forced by quinn: the congestion controller is fixed at
//! connect time (quinn cannot swap it post-handshake), so Brutal is installed
//! from the client's configured TX bound rather than the server's advertised RX
//! (the `min(serverRx, clientTx)` refinement is reported in [`HandshakeInfo`] but
//! not applied to pacing); the bandwidth-detection (`auto`) and BBR paths fall
//! back to quinn's built-in BBR.

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use bytes::Bytes;
use quinn::VarInt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::task::JoinHandle;

use crate::client::config::Config;
use crate::client::hop_socket::HopUdpSocket;
use crate::client::obfs_socket::ObfsUdpSocket;
use crate::client::tls::build_rustls_client_config;
use crate::client::udp::SendError;
use crate::client::udp::UdpConn;
use crate::client::udp::UdpIo;
use crate::client::udp::UdpSessionManager;
use crate::errors::AuthError;
use crate::errors::ConnectError;
use crate::errors::DialError;
use crate::internal::congestion::brutal::BrutalConfig;
use crate::internal::obfs::SalamanderObfuscator;
use crate::internal::protocol;
use crate::internal::protocol::AuthRequest;
use crate::internal::protocol::UdpMessage;

// HTTP/3 connection-close error codes (mirrors Go's closeErrCode*).
const CLOSE_ERR_CODE_OK: u32 = 0x100;
const CLOSE_ERR_CODE_PROTOCOL_ERROR: u32 = 0x101;

/// The HTTP/3 request handle. Kept alive for the connection's lifetime: dropping
/// the last `SendRequest` makes h3 shut the connection down (Go keeps the
/// RoundTripper/conn alive), which would kill the raw proxy streams.
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Case-insensitive [`protocol::Header`] over an `http::HeaderMap`, so the ported
/// auth header logic works directly against HTTP/3 request/response headers.
impl protocol::Header for http::HeaderMap {
    fn get(&self, key: &str) -> Option<&str> {
        http::HeaderMap::get(self, key).and_then(|v| v.to_str().ok())
    }

    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(val)) = (
            http::HeaderName::try_from(key),
            http::HeaderValue::try_from(value),
        ) {
            self.insert(name, val);
        }
    }
}

/// What the handshake learned about the connection.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub udp_enabled: bool,
    /// Effective TX bandwidth (`min(serverRx, clientTx)`), 0 if unknown/auto.
    pub tx: u64,
    pub server_addr: SocketAddr,
}

/// A connected Hysteria 2 client.
pub struct Client {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    udp_sm: Option<UdpSessionManager<QuinnUdpIo>>,
    /// When set, [`Client::tcp`] returns before the server's TCP response is
    /// read, deferring it to the first read (Go's `FastOpen`).
    fast_open: bool,
    // The HTTP/3 driver task and request handle; both kept alive for the
    // connection's lifetime so it isn't torn down after auth.
    _h3_driver: JoinHandle<()>,
    _h3_send_request: H3SendRequest,
}

impl Client {
    /// Dial the server, authenticate, and return the client plus handshake info.
    pub async fn connect(mut config: Config) -> Result<(Self, HandshakeInfo)> {
        config.verify_and_fill()?;
        // Normalise IPv4-mapped IPv6 (e.g. `::ffff:1.2.3.4`) to plain IPv4 so the
        // bind socket family and the dial target agree on dual-stack-disabled hosts.
        config
            .server_addr
            .set_ip(config.server_addr.ip().to_canonical());

        let client_config = build_quic_client_config(&config)?;
        let bind: SocketAddr = if config.server_addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = build_endpoint(bind, &config)?;

        let conn = endpoint
            .connect_with(client_config, config.server_addr, &config.tls.server_name)
            .map_err(|e| ConnectError { err: Box::new(e) })?
            .await
            .map_err(|e| ConnectError { err: Box::new(e) })?;

        let info = authenticate(&conn, &config).await?;

        let udp_sm = if info.udp_enabled {
            Some(UdpSessionManager::new(Arc::new(QuinnUdpIo {
                conn: conn.clone(),
            })))
        } else {
            None
        };

        Ok((
            Self {
                endpoint,
                conn,
                udp_sm,
                fast_open: config.fast_open,
                _h3_driver: info.h3_driver,
                _h3_send_request: info.send_request,
            },
            HandshakeInfo {
                udp_enabled: info.udp_enabled,
                tx: info.tx,
                server_addr: config.server_addr,
            },
        ))
    }

    /// Open a proxied TCP connection to `addr` (`host:port`).
    pub async fn tcp(&self, addr: &str) -> Result<TcpConn> {
        let (mut send, mut recv) =
            self.conn
                .open_bi()
                .await
                .map_err(|e| crate::errors::ClosedError {
                    err: Some(Box::new(e)),
                })?;

        let mut request = Vec::new();
        protocol::write_tcp_request(&mut request, addr)?;
        send.write_all(&request)
            .await
            .context("write TCP request")?;

        if self.fast_open {
            // Don't wait for the response; defer it to the first read, as Go's
            // FastOpen does (`tcpConn{Established: false}`). The future owns the
            // recv stream and hands it back once the response is validated.
            let pending: ResponseFuture = Box::pin(async move {
                let ((ok, msg), leftover) = read_tcp_response(&mut recv)
                    .await
                    .map_err(io::Error::other)?;
                if !ok {
                    return Err(io::Error::other(DialError { message: msg }));
                }
                Ok((recv, leftover))
            });
            return Ok(TcpConn {
                send,
                recv: RecvState::AwaitingResponse(pending),
            });
        }

        let ((ok, msg), leftover) = read_tcp_response(&mut recv).await?;
        if !ok {
            return Err(DialError { message: msg }.into());
        }
        Ok(TcpConn {
            send,
            recv: RecvState::Ready {
                recv,
                leftover,
                leftover_pos: 0,
            },
        })
    }

    /// Open a new UDP relay session, if the server enabled UDP.
    pub fn udp(&self) -> Result<UdpConn<QuinnUdpIo>> {
        let sm = self.udp_sm.as_ref().ok_or_else(|| DialError {
            message: "UDP not enabled".into(),
        })?;
        sm.new_udp().map_err(Into::into)
    }

    /// Close the connection.
    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(CLOSE_ERR_CODE_OK), b"");
        self.endpoint
            .close(VarInt::from_u32(CLOSE_ERR_CODE_OK), b"");
    }
}

impl Drop for Client {
    /// Close on drop (RAII). The HTTP/3 driver task holds a clone of the
    /// connection and loops until it closes, so without this a `Client` dropped
    /// without an explicit [`close`](Self::close) would leak the task and the
    /// connection. Idempotent — closing an already-closed connection is a no-op.
    fn drop(&mut self) {
        self.close();
    }
}

/// Internal result of the auth handshake.
struct AuthOutcome {
    udp_enabled: bool,
    tx: u64,
    h3_driver: JoinHandle<()>,
    send_request: H3SendRequest,
}

async fn authenticate(conn: &quinn::Connection, config: &Config) -> Result<AuthOutcome> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| ConnectError { err: Box::new(e) })?;

    // Drive the HTTP/3 connection in the background for its lifetime.
    let h3_driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let uri = format!("https://{}{}", protocol::URL_HOST, protocol::URL_PATH);
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .body(())
        .context("build auth request")?;
    protocol::auth_request_to_header(
        request.headers_mut(),
        &AuthRequest {
            auth: config.auth.clone(),
            rx: config.bandwidth.max_rx,
        },
    );

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| ConnectError { err: Box::new(e) })?;
    stream
        .finish()
        .await
        .map_err(|e| ConnectError { err: Box::new(e) })?;
    let response = stream
        .recv_response()
        .await
        .map_err(|e| ConnectError { err: Box::new(e) })?;

    if response.status().as_u16() != protocol::STATUS_AUTH_OK {
        conn.close(VarInt::from_u32(CLOSE_ERR_CODE_PROTOCOL_ERROR), b"");
        return Err(AuthError {
            status_code: i32::from(response.status().as_u16()),
        }
        .into());
    }

    let auth_resp = protocol::auth_response_from_header(response.headers());
    // quinn fixes congestion control at connect; tx here is informational.
    let tx = effective_tx(auth_resp.rx_auto, auth_resp.rx, config.bandwidth.max_tx);

    Ok(AuthOutcome {
        udp_enabled: auth_resp.udp_enabled,
        tx,
        h3_driver,
        send_request,
    })
}

/// Effective TX bandwidth after auth (Go's `actualTx`): bandwidth detection
/// (`auto`) ⇒ 0; a server RX of 0 or larger than our TX ⇒ our configured TX;
/// otherwise the smaller server RX (`min(serverRx, clientTx)`).
fn effective_tx(rx_auto: bool, server_rx: u64, client_tx: u64) -> u64 {
    if rx_auto {
        0
    } else if server_rx == 0 || server_rx > client_tx {
        client_tx
    } else {
        server_rx
    }
}

/// Build the quinn client config: rustls (pinning) + transport tunables +
/// congestion controller (Brutal from the configured TX, else BBR).
fn build_quic_client_config(config: &Config) -> Result<quinn::ClientConfig> {
    let rustls_config = build_rustls_client_config(&config.tls)?;
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| anyhow!("QUIC TLS config: {e}"))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    // quinn only exposes the *max* receive windows (it grows the window
    // adaptively), so the `initial_*_receive_window` config fields are still
    // validated/defaulted but have no quinn setter to plumb them into.
    transport.stream_receive_window(to_varint(config.quic.max_stream_receive_window)?);
    transport.receive_window(to_varint(config.quic.max_connection_receive_window)?);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(config.quic.max_idle_timeout)
            .map_err(|e| anyhow!("max idle timeout: {e}"))?,
    ));
    transport.keep_alive_interval(Some(config.quic.keep_alive_period));
    // Enable QUIC datagrams (UDP relay).
    transport.datagram_receive_buffer_size(Some(protocol::MAX_UDP_SIZE * 1024));
    transport.datagram_send_buffer_size(protocol::MAX_UDP_SIZE * 1024);
    if config.quic.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }

    if config.bandwidth.max_tx > 0 {
        transport.congestion_controller_factory(Arc::new(BrutalConfig {
            bps: config.bandwidth.max_tx,
        }));
    } else {
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }

    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn to_varint(value: u64) -> Result<VarInt> {
    VarInt::from_u64(value).map_err(|e| anyhow!("value exceeds QUIC varint range: {e}"))
}

/// Build the client endpoint bound to `bind`, composing the UDP socket layers:
/// raw → Salamander obfuscation (if `obfs` set) → port hopping (if `hop_ports`
/// set), matching Go's stack (obfs wraps the per-socket conn, udphop rotates it).
fn build_endpoint(bind: SocketAddr, config: &Config) -> Result<quinn::Endpoint> {
    // Destination addresses to hop across: each port at the server's IP.
    let hop_addrs: Option<Vec<SocketAddr>> = config.hop_ports.as_ref().and_then(|ports| {
        let ip = config.server_addr.ip();
        let addrs: Vec<SocketAddr> = ports
            .ports()
            .into_iter()
            .map(|p| SocketAddr::new(ip, p))
            .collect();
        (!addrs.is_empty()).then_some(addrs)
    });

    if config.obfs.is_none() && hop_addrs.is_none() {
        return quinn::Endpoint::client(bind).context("bind QUIC endpoint");
    }

    let runtime = quinn::default_runtime()
        .ok_or_else(|| anyhow!("no async runtime found; call within a tokio runtime"))?;
    let std_socket = std::net::UdpSocket::bind(bind).context("bind UDP socket")?;
    let mut socket = runtime
        .wrap_udp_socket(std_socket)
        .context("wrap UDP socket")?;

    if let Some(psk) = config.obfs.as_deref() {
        socket = Arc::new(ObfsUdpSocket::new(socket, SalamanderObfuscator::new(psk)?));
    }
    if let Some(addrs) = hop_addrs {
        socket = Arc::new(HopUdpSocket::new(
            socket,
            config.server_addr,
            addrs,
            config.hop_interval,
        ));
    }

    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .context("create QUIC endpoint")
}

/// Read a TCP response from `recv`, returning it plus any stream bytes read past
/// the response header (the start of the proxied data). Reuses the sync parser
/// by retrying on a growing buffer until it stops needing more bytes.
async fn read_tcp_response(recv: &mut quinn::RecvStream) -> Result<((bool, String), Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let mut cursor = io::Cursor::new(&buf[..]);
        match protocol::read_tcp_response(&mut cursor) {
            Ok(resp) => {
                let consumed = usize::try_from(cursor.position()).unwrap_or(0);
                return Ok((resp, buf[consumed..].to_vec()));
            },
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // quinn's inherent read returns None when the stream is finished.
                let Some(n) = recv.read(&mut chunk).await.context("read TCP response")? else {
                    return Err(anyhow!("connection closed before TCP response completed"));
                };
                buf.extend_from_slice(&chunk[..n]);
            },
            Err(e) => return Err(e.into()),
        }
    }
}

/// Resolves to the recv stream plus any bytes read past the TCP response header,
/// once the deferred (fast-open) response has been read and validated.
type ResponseFuture =
    Pin<Box<dyn Future<Output = io::Result<(quinn::RecvStream, Vec<u8>)>> + Send>>;

/// Receive side of a [`TcpConn`].
enum RecvState {
    /// Fast-open: the TCP response hasn't been read yet; the first read drives
    /// this future, which yields the recv stream and any post-response bytes.
    AwaitingResponse(ResponseFuture),
    /// Response read: serve `leftover` (post-response bytes), then the stream.
    Ready {
        recv: quinn::RecvStream,
        leftover: Vec<u8>,
        leftover_pos: usize,
    },
}

/// A proxied TCP connection: a QUIC bidi stream, with any post-response bytes
/// replayed before further reads. Implements `tokio` `AsyncRead`/`AsyncWrite`.
pub struct TcpConn {
    send: quinn::SendStream,
    recv: RecvState,
}

impl AsyncRead for TcpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut self.recv {
                RecvState::AwaitingResponse(fut) => {
                    // Drive the deferred response read; on success, transition to
                    // Ready and loop to serve the (re)read.
                    let (recv, leftover) = match fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(v)) => v,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    };
                    self.recv = RecvState::Ready {
                        recv,
                        leftover,
                        leftover_pos: 0,
                    };
                },
                RecvState::Ready {
                    recv,
                    leftover,
                    leftover_pos,
                } => {
                    if *leftover_pos < leftover.len() {
                        let remaining = &leftover[*leftover_pos..];
                        let n = remaining.len().min(buf.remaining());
                        buf.put_slice(&remaining[..n]);
                        *leftover_pos += n;
                        return Poll::Ready(Ok(()));
                    }
                    return AsyncRead::poll_read(Pin::new(recv), cx, buf);
                },
            }
        }
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// [`UdpIo`] over a QUIC connection's datagrams (Go's `udpIOImpl`).
pub struct QuinnUdpIo {
    conn: quinn::Connection,
}

impl UdpIo for QuinnUdpIo {
    async fn receive_message(&self) -> io::Result<UdpMessage> {
        loop {
            let datagram = self.conn.read_datagram().await.map_err(io::Error::other)?;
            // Invalid datagram: skip it and wait for the next, like Go.
            if let Ok(msg) = protocol::parse_udp_message(&datagram) {
                return Ok(msg);
            }
        }
    }

    fn send_message(&self, buf: &mut [u8], msg: &UdpMessage) -> Result<(), SendError> {
        let Some(n) = msg.serialize(buf) else {
            // Larger than the scratch buffer: silent drop, as in Go.
            return Ok(());
        };
        match self.conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
            Ok(()) => Ok(()),
            // TooLarge implies datagrams are enabled, so max_datagram_size is
            // Some; guard the impossible None rather than silently dropping
            // (a 0 max would make frag_udp_message produce no fragments).
            Err(quinn::SendDatagramError::TooLarge) => match self.conn.max_datagram_size() {
                Some(max_payload_size) => Err(SendError::TooLarge { max_payload_size }),
                None => Err(SendError::Io(io::Error::other(
                    "datagram too large but max datagram size is unknown",
                ))),
            },
            Err(e) => Err(SendError::Io(io::Error::other(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn effective_tx_matches_go_rules() {
        assert_eq!(
            effective_tx(true, 100, 200),
            0,
            "auto ⇒ bandwidth detection"
        );
        assert_eq!(
            effective_tx(false, 0, 200),
            200,
            "server rx 0 (unlimited) ⇒ client tx",
        );
        assert_eq!(
            effective_tx(false, 300, 200),
            200,
            "server rx > client tx ⇒ client tx",
        );
        assert_eq!(
            effective_tx(false, 150, 200),
            150,
            "server rx ≤ client tx ⇒ server rx",
        );
    }
}
