//! End-to-end conformance test for `transport-socks5 --socks5`: a SOCKS5 client drives
//! transport-socks5, which tunnels through the Hysteria 2 client to the reference server
//! and out to a local target. Proves the full chain
//! `SOCKS5 → transport-socks5 → hysteria → server → target`.

mod common;

use std::io;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use common::HysteriaServer;
use common::HysteriaServerOptions;
use hysteria::client::Client;
use hysteria::client::config::Config;
use hysteria::client::config::TlsConfig;
use pretty_assertions::assert_eq;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::version::TLS13;
use rustls_native_certs::load_native_certs;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::pem::PemObject as _;
use tokio::io::AsyncBufReadExt as _;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::process::Child;
use tokio::process::Command;
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_socks::tcp::Socks5Stream;

fn client_config(cfg: &common::HysteriaClientConfig) -> Result<Config> {
    // Path is reported by our own test harness (trusted), not user input.
    let pem = std::fs::read(&cfg.ca_cert_path).context("read reference server cert")?; // nosemgrep
    let cert = CertificateDer::from_pem_slice(&pem).map_err(|e| anyhow!("parse cert: {e}"))?;
    let tls = TlsConfig {
        server_name: cfg.sni.clone(),
        ca: Some(cert.as_ref().to_vec()),
    };
    Ok(Config::new(
        cfg.server.parse().context("server addr")?,
        cfg.auth.clone(),
        tls,
    ))
}

/// Boot the reference server and start transport-socks5's SOCKS5 front-end over it;
/// returns the SOCKS5 listen address (and keeps the server alive via the return).
async fn start_bridge(server: &HysteriaServer) -> Result<SocketAddr> {
    let (client, _info) = Client::connect(client_config(server.config())?).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = transport_socks5::serve(listener, Arc::new(client)).await;
    });
    Ok(addr)
}

async fn spawn_tcp_echo() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(addr)
}

/// Append a SOCKS5 IPv4 address + port.
fn push_v4(buf: &mut Vec<u8>, addr: SocketAddr) -> Result<()> {
    let SocketAddr::V4(v4) = addr else {
        bail!("expected IPv4 target")
    };
    buf.push(0x01);
    buf.extend_from_slice(&v4.ip().octets());
    buf.extend_from_slice(&v4.port().to_be_bytes());
    Ok(())
}

/// Spawn the actual `transport-socks5` binary over the reference server and return its
/// SOCKS5 listen address (parsed from its startup output) plus the child handle
/// (kept alive; killed on drop).
async fn spawn_bridge_binary(server: &HysteriaServer) -> Result<(SocketAddr, Child)> {
    let cfg = server.config();
    // Drive the binary through its public surface: a `hysteria2://` link, plus
    // `--ca` to trust the reference server's self-signed cert.
    let url = format!(
        "hysteria2://{auth}@{server}/?sni={sni}",
        auth = cfg.auth,
        server = cfg.server,
        sni = cfg.sni,
    );
    let ca = cfg
        .ca_cert_path
        .to_str()
        .context("cert path is not UTF-8")?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_transport-socks5"))
        .args(["--socks5", "127.0.0.1:0", "--url", &url, "--ca", ca])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn transport-socks5 binary")?;

    let stderr = child
        .stderr
        .take()
        .context("transport-socks5 stderr unavailable")?;
    let mut lines = BufReader::new(stderr).lines();
    loop {
        let line = timeout(Duration::from_secs(15), lines.next_line())
            .await
            .context("transport-socks5 startup timed out")??
            .context("transport-socks5 exited before it started listening")?;
        if let Some(addr) = line.strip_prefix("SOCKS5 listening on ") {
            return Ok((
                addr.trim().parse().context("parse SOCKS5 listen addr")?,
                child,
            ));
        }
    }
}

/// Perform the SOCKS5 no-auth greeting; leaves the stream ready for a request.
async fn socks_greet(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [0x05, 0x00] {
        bail!("unexpected method reply {reply:?}");
    }
    Ok(())
}

#[tokio::test]
async fn socks5_connect_tunnels_tcp() -> Result<()> {
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;
    let echo_addr = spawn_tcp_echo().await?;
    let socks_addr = start_bridge(&server).await?;

    let mut stream = TcpStream::connect(socks_addr).await?;
    socks_greet(&mut stream).await?;

    // CONNECT to the echo server.
    let mut request = vec![0x05, 0x01, 0x00];
    push_v4(&mut request, echo_addr)?;
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT succeeds");

    // The stream is now a tunnel to the echo server.
    let payload = b"hello through socks5";
    stream.write_all(payload).await?;
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await?;
    assert_eq!(&got, payload, "TCP echoes back through SOCKS5 + hysteria");
    Ok(())
}

#[tokio::test]
async fn socks5_udp_associate_tunnels_udp() -> Result<()> {
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;

    // Local UDP echo server.
    let echo = UdpSocket::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            if echo.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });

    let socks_addr = start_bridge(&server).await?;

    // Open the UDP association over a TCP control connection (kept alive).
    let mut ctrl = TcpStream::connect(socks_addr).await?;
    socks_greet(&mut ctrl).await?;
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut reply = [0u8; 10];
    ctrl.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 UDP ASSOCIATE succeeds");
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    // Send a SOCKS5 UDP datagram (RSV, RSV, FRAG, ATYP, addr, port, data).
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let payload = b"udp through socks5";
    let mut datagram = vec![0x00, 0x00, 0x00];
    push_v4(&mut datagram, echo_addr)?;
    datagram.extend_from_slice(payload);
    client.send_to(&datagram, relay).await?;

    let mut buf = [0u8; 2048];
    let (n, _from) = timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .context("UDP reply timed out")??;
    // Reply header: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + port(2) = 10 bytes.
    assert_eq!(
        &buf[10..n],
        payload,
        "UDP echoes back through SOCKS5 + hysteria"
    );

    drop(ctrl); // ends the association
    Ok(())
}

/// True if `needle` appears anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// e2e: a real SOCKS5 client (`tokio-socks`) → our `transport-socks5` binary → reference
/// hysteria server → the public internet, fetching `https://example.com` over
/// TLS. Requires outbound network access.
#[tokio::test]
async fn socks5_client_opens_https_example_com() -> Result<()> {
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;
    let (socks_addr, _bridge) = spawn_bridge_binary(&server).await?;

    // Open a tunnel to example.com:443 through transport-socks5 with a real SOCKS5 client.
    let tunnel = Socks5Stream::connect(socks_addr, ("example.com", 443u16))
        .await
        .context("SOCKS5 CONNECT to example.com:443")?;

    // TLS over the tunnel, verified against the system root store. Loading the
    // store is blocking, so run it off the async runtime.
    let native = spawn_blocking(load_native_certs)
        .await
        .context("load native certs")?;
    let mut roots = RootCertStore::empty();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    let tls_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .context("build TLS config")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let domain = ServerName::try_from("example.com")?;
    let mut tls = connector
        .connect(domain, tunnel)
        .await
        .context("TLS handshake")?;

    // Fetch the page over HTTPS.
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .context("send HTTP request")?;

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = timeout(Duration::from_secs(30), tls.read(&mut buf))
            .await
            .context("reading https://example.com timed out")?;
        match read {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            // Some servers close without a TLS close_notify; treat as end of body.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("read HTTPS response"),
        }
        if contains(&response, b"Example Domain") {
            break;
        }
    }

    assert!(
        contains(&response, b"Example Domain"),
        "the fetched HTML must contain \"Example Domain\"",
    );
    Ok(())
}
