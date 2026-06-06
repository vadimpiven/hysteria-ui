//! End-to-end conformance test for the Hysteria 2 client transport against the
//! reference server (booted via the Node harness). Proves the whole path: QUIC
//! dial + TLS cert pinning + HTTP/3 auth + relay, by echoing bytes through the
//! tunnel to a local target server.

mod common;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use common::HysteriaServer;
use common::HysteriaServerOptions;
use hysteria::client::Client;
use hysteria::client::config::Config;
use hysteria::client::config::TlsConfig;
use hysteria::client::config::parse_port_union;
use pretty_assertions::assert_eq;
use serde_json::json;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

/// Parse a colon-hex SHA-256 fingerprint (the `pinSHA256` link param).
fn parse_pin(s: &str) -> Result<[u8; 32]> {
    let bytes = s
        .split(':')
        .map(|h| u8::from_str_radix(h, 16))
        .collect::<Result<Vec<u8>, _>>()
        .context("invalid pin hex")?;
    bytes.try_into().map_err(|_| anyhow!("pin is not 32 bytes"))
}

/// Build a client `Config` from the harness's reported server config.
fn client_config(cfg: &common::HysteriaClientConfig) -> Result<Config> {
    let tls = TlsConfig {
        server_name: cfg.sni.clone(),
        insecure: cfg.insecure,
        pin_sha256: Some(parse_pin(&cfg.pin_sha256)?),
        ca: None,
    };
    Ok(Config::new(
        cfg.server.parse().context("server addr")?,
        cfg.auth.clone(),
        tls,
    ))
}

/// A local TCP echo server; returns its address. Echoes until each peer closes.
async fn spawn_tcp_echo() -> Result<std::net::SocketAddr> {
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

#[tokio::test]
async fn tcp_relay_echoes_through_the_tunnel() -> Result<()> {
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;
    let echo_addr = spawn_tcp_echo().await?;

    let (client, info) = Client::connect(client_config(server.config())?).await?;

    let mut conn = client.tcp(&echo_addr.to_string()).await?;
    let payload = b"hello hysteria over quic";
    conn.write_all(payload).await.context("write to tunnel")?;
    conn.flush().await.context("flush tunnel")?;

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.context("read echo")?;
    assert_eq!(&got, payload, "TCP payload round-trips through the tunnel");

    // Sanity: server address is reported back.
    assert_eq!(
        info.server_addr,
        server.config().server.parse()?,
        "handshake reports server addr"
    );

    client.close();
    Ok(())
}

#[tokio::test]
async fn tcp_relay_with_salamander_obfuscation() -> Result<()> {
    // Boot the server with Salamander obfs; the client must obfuscate to match,
    // which exercises BLAKE2b-256 interop with the Go reference.
    let options = HysteriaServerOptions::default().with_config(json!({
        "obfs": { "type": "salamander", "salamander": { "password": "obfs-password" } },
    }));
    let server = HysteriaServer::serve(options).await?;
    let echo_addr = spawn_tcp_echo().await?;

    let mut config = client_config(server.config())?;
    let obfs = server
        .config()
        .obfs
        .as_ref()
        .context("server reported no obfs")?;
    config.obfs = Some(obfs.password.clone().into_bytes());

    let (client, _info) = Client::connect(config).await?;
    let mut conn = client.tcp(&echo_addr.to_string()).await?;
    let payload = b"hello through salamander";
    conn.write_all(payload)
        .await
        .context("write to obfuscated tunnel")?;
    conn.flush().await.context("flush")?;

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.context("read echo")?;
    assert_eq!(
        &got, payload,
        "payload round-trips through the obfuscated tunnel"
    );

    client.close();
    Ok(())
}

#[tokio::test]
async fn tcp_relay_with_fast_open() -> Result<()> {
    // Fast open returns the conn before the server's TCP response; the response
    // is read lazily on the first read. The echo must still round-trip.
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;
    let echo_addr = spawn_tcp_echo().await?;

    let mut config = client_config(server.config())?;
    config.fast_open = true;

    let (client, _info) = Client::connect(config).await?;
    let mut conn = client.tcp(&echo_addr.to_string()).await?;
    let payload = b"fast open hello";
    conn.write_all(payload).await.context("write")?;
    conn.flush().await.context("flush")?;

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.context("read echo")?;
    assert_eq!(&got, payload, "payload round-trips with fast open");

    client.close();
    Ok(())
}

#[tokio::test]
async fn tcp_relay_with_port_hopping() -> Result<()> {
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;
    let echo_addr = spawn_tcp_echo().await?;

    let mut config = client_config(server.config())?;
    // A single-port "range" (the server's actual port) exercises the hopping
    // socket end-to-end; multi-port hopping needs a port-range/firewall server.
    let port = config.server_addr.port().to_string();
    config.hop_ports = Some(parse_port_union(&port).context("port union")?);

    let (client, _info) = Client::connect(config).await?;
    let mut conn = client.tcp(&echo_addr.to_string()).await?;
    let payload = b"hop through the tunnel";
    conn.write_all(payload).await.context("write")?;
    conn.flush().await.context("flush")?;

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.context("read echo")?;
    assert_eq!(
        &got, payload,
        "payload round-trips through the port-hopping socket"
    );

    client.close();
    Ok(())
}

#[tokio::test]
async fn udp_relay_echoes_through_the_tunnel() -> Result<()> {
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

    let (client, info) = Client::connect(client_config(server.config())?).await?;
    if !info.udp_enabled {
        // Server didn't enable UDP; nothing to assert.
        client.close();
        return Ok(());
    }

    let udp = client.udp()?;
    let payload = b"ping over udp";
    udp.send(payload, &echo_addr.to_string())
        .map_err(|e| anyhow!("udp send: {e}"))?;

    let (data, _addr) = tokio::time::timeout(std::time::Duration::from_secs(5), udp.receive())
        .await
        .context("udp receive timed out")??;
    assert_eq!(data, payload, "UDP payload round-trips through the tunnel");

    client.close();
    Ok(())
}
