//! Dev-only SOCKS5 front-end over the Hysteria 2 client (PLAN §5 `devproxy`).
//!
//! The SOCKS5 protocol (RFC 1928) — greeting, no-auth negotiation, request
//! parsing, and UDP datagram framing — is delegated to `fast-socks5`. We only
//! wire its commands to the [`hysteria::client::Client`]: `CONNECT` maps to
//! [`Client::tcp`] and `UDP ASSOCIATE` to a [`Client::udp`] session. This is the
//! local conformance loop for the protocol — never part of the shipped surface.
//!
//! `SocketAddr` is a `std::net` address *value type* that `tokio` reuses (it has
//! no replacement); all I/O uses `tokio::net`.

// Dev-only binary's status output to stderr is intentional.
#![expect(clippy::print_stderr, reason = "dev-only binary status output")]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use clap::Parser;
use fast_socks5::ReplyError;
use fast_socks5::Socks5Command;
use fast_socks5::new_udp_header;
use fast_socks5::parse_udp_request;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::server::states::CommandRead;
use hysteria::client::Client;
use hysteria::client::config::Config;
use tokio::io::AsyncReadExt as _;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

/// `devproxy` command-line arguments.
#[derive(Parser, Debug)]
#[command(about = "Dev-only SOCKS5 proxy over the Hysteria 2 client")]
pub struct Cli {
    /// Address to listen on for SOCKS5 clients.
    #[arg(long, value_name = "ADDR")]
    pub socks5: SocketAddr,
    /// Hysteria 2 connection link (`hysteria2://auth@host:port/?params`).
    #[arg(long, value_name = "URL")]
    pub url: String,
}

impl Cli {
    /// Split into the SOCKS5 listen address and the hysteria client config,
    /// parsing the `hysteria2://` link into a `profile::Profile` (via the
    /// `config` crate) and building the client config from it.
    pub fn into_parts(self) -> Result<(SocketAddr, Config)> {
        let profile = config::parse_uri(&self.url)
            .ok_or_else(|| anyhow!("not a hysteria2:// link: {}", self.url))?;
        let config = Config::from_profile(&profile).context("build client config from link")?;
        Ok((self.socks5, config))
    }
}

/// Connect to the server, then serve SOCKS5 until the listener errors.
pub async fn run(cli: Cli) -> Result<()> {
    // into_parts resolves the server address (a blocking DNS lookup for a
    // hostname), so keep it off the async executor thread.
    let (listen, config) = tokio::task::spawn_blocking(move || cli.into_parts())
        .await
        .context("join DNS resolution")??;
    let server = config.server_addr;
    let (client, info) = Client::connect(config).await.context("connect to server")?;
    eprintln!(
        "connected to {server} (udp_enabled={}, tx={})",
        info.udp_enabled, info.tx
    );

    let listener = TcpListener::bind(listen)
        .await
        .context("bind SOCKS5 listener")?;
    eprintln!("SOCKS5 listening on {}", listener.local_addr()?);
    serve(listener, Arc::new(client)).await
}

/// Serve SOCKS5 over `listener`, tunnelling every connection through `client`,
/// until the listener errors.
pub async fn serve(listener: TcpListener, client: Arc<Client>) -> Result<()> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .context("accept SOCKS5 connection")?;
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            // Per-connection errors are local; just drop the connection.
            let _ = handle(stream, client).await;
        });
    }
}

/// Run the SOCKS5 handshake (delegated to `fast-socks5`) and dispatch the command.
async fn handle(stream: TcpStream, client: Arc<Client>) -> Result<()> {
    let (proto, cmd, target) = Socks5ServerProtocol::accept_no_auth(stream)
        .await
        .context("SOCKS5 handshake")?
        .read_command()
        .await
        .context("read SOCKS5 command")?;

    match cmd {
        Socks5Command::TCPConnect => handle_connect(proto, target.to_string(), client).await,
        Socks5Command::UDPAssociate => handle_udp_associate(proto, client).await,
        Socks5Command::TCPBind => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            bail!("SOCKS5 BIND is not supported");
        },
    }
}

/// `CONNECT`: open a tunnel to `target`, then splice it to the SOCKS client.
async fn handle_connect(
    proto: Socks5ServerProtocol<TcpStream, CommandRead>,
    target: String,
    client: Arc<Client>,
) -> Result<()> {
    let mut tunnel = match client.tcp(&target).await {
        Ok(conn) => conn,
        Err(e) => {
            proto.reply_error(&ReplyError::HostUnreachable).await?;
            return Err(e.context("open tunnel"));
        },
    };
    // fast-socks5 writes the success reply; reclaim the raw stream to splice.
    let mut stream = proto
        .reply_success(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await?;
    copy_bidirectional(&mut stream, &mut tunnel)
        .await
        .context("relay TCP")?;
    Ok(())
}

/// `UDP ASSOCIATE`: bridge a local relay socket to a [`Client::udp`] session,
/// using `fast-socks5` for the SOCKS5 UDP datagram framing.
async fn handle_udp_associate(
    proto: Socks5ServerProtocol<TcpStream, CommandRead>,
    client: Arc<Client>,
) -> Result<()> {
    let relay = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .context("bind UDP relay")?;
    let relay_addr = relay.local_addr().context("relay addr")?;
    let session = match client.udp() {
        Ok(session) => session,
        Err(e) => {
            proto.reply_error(&ReplyError::GeneralFailure).await?;
            return Err(e.context("open UDP session"));
        },
    };
    // Tell the SOCKS client where to send datagrams; keep the TCP control stream
    // — the association lives as long as it stays open.
    let mut control = proto.reply_success(relay_addr).await?;

    let mut packet = vec![0u8; 65535];
    let mut ctrl_buf = [0u8; 256];
    let mut client_addr: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            // SOCKS client → tunnel.
            recv = relay.recv_from(&mut packet) => {
                let (n, from) = recv.context("recv from SOCKS UDP")?;
                client_addr = Some(from);
                // fast-socks5 parses the SOCKS5 UDP request; drop fragments (frag != 0).
                if let Ok((0, target, data)) = parse_udp_request(&packet[..n]).await {
                    let _ = session.send(data, &target.to_string());
                }
            }
            // Tunnel → SOCKS client.
            received = session.receive() => {
                let (data, from) = received.context("receive from tunnel")?;
                if let (Some(dst), Ok(addr)) = (client_addr, from.parse::<SocketAddr>()) {
                    // fast-socks5 builds the SOCKS5 UDP reply header.
                    if let Ok(mut reply) = new_udp_header(addr) {
                        reply.extend_from_slice(&data);
                        relay.send_to(&reply, dst).await.context("send to SOCKS UDP")?;
                    }
                }
            }
            // The TCP control connection closing ends the association.
            read = control.read(&mut ctrl_buf) => {
                if matches!(read, Ok(0) | Err(_)) {
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn cli_into_parts_parses_link() -> Result<()> {
        let cli = Cli::try_parse_from([
            "devproxy",
            "--socks5",
            "127.0.0.1:1080",
            "--url",
            "hysteria2://secret@10.0.0.1:443/?obfs=salamander&obfs-password=pw&sni=example.com&insecure=1",
        ])?;
        let (listen, config) = cli.into_parts()?;
        assert_eq!(listen, "127.0.0.1:1080".parse()?, "listen address");
        assert_eq!(
            config.server_addr,
            "10.0.0.1:443".parse()?,
            "server address"
        );
        assert_eq!(config.auth, "secret", "auth");
        assert_eq!(config.tls.server_name, "example.com", "sni");
        assert!(config.tls.insecure, "insecure flag");
        assert_eq!(config.obfs, Some(b"pw".to_vec()), "obfs psk");
        Ok(())
    }

    #[test]
    fn cli_into_parts_rejects_non_link() -> Result<()> {
        let cli = Cli::try_parse_from([
            "devproxy",
            "--socks5",
            "127.0.0.1:1080",
            "--url",
            "https://example.com/",
        ])?;
        assert!(cli.into_parts().is_err(), "non-hysteria2 URL rejected");
        Ok(())
    }
}
