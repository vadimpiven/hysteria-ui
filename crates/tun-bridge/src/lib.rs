//! A dev TUN front-end over the Hysteria 2 client.
//!
//! Opens a macOS `utun` via `tun-rs` (no `NetworkExtension`, no FFI), connects the
//! `hysteria` client from a `hysteria2://` link, and drives the `tunnel`
//! netstack so traffic routed into the TUN is proxied. The TUN counterpart to
//! `socks5-bridge`; never linked into the shipped FFI libraries.
//!
//! Steering traffic into the TUN (adding routes) needs root and is done
//! out-of-band; this binary only opens the device and runs the netstack.

// The binary prints status to stderr.
#![expect(clippy::print_stderr, reason = "CLI status output")]

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use hysteria::client::Client;
use hysteria::client::config::Config;
use tun_rs::DeviceBuilder;

/// `tun-bridge` command-line arguments.
#[derive(Parser, Debug)]
#[command(about = "Dev TUN proxy over the Hysteria 2 client")]
pub struct Cli {
    /// Hysteria 2 connection link (`hysteria2://auth@host:port/?params`).
    #[arg(long, value_name = "URL")]
    pub url: String,
    /// Address to assign to the TUN interface (also the netstack's on-link addr).
    #[arg(long, value_name = "IPV4", default_value = "10.0.0.1")]
    pub tun_addr: Ipv4Addr,
    /// Prefix length of the TUN subnet.
    #[arg(long, default_value_t = 24)]
    pub tun_prefix: u8,
    /// TUN MTU.
    #[arg(long, default_value_t = 1500)]
    pub mtu: u16,
}

/// Connect to the server, open the TUN, and run the netstack until it errors.
pub async fn run(cli: Cli) -> Result<()> {
    // Parsing + DNS resolution block, so keep them off the async executor.
    let url = cli.url.clone();
    let config = tokio::task::spawn_blocking(move || build_config(&url))
        .await
        .context("join client config build")??;
    let server = config.server_addr;
    let (client, info) = Client::connect(config).await.context("connect to server")?;
    eprintln!(
        "connected to {server} (udp_enabled={}, tx={})",
        info.udp_enabled, info.tx
    );

    let device = Arc::new(
        DeviceBuilder::new()
            .ipv4(cli.tun_addr, cli.tun_prefix, None)
            .mtu(cli.mtu)
            .build_async()
            .context("open TUN device")?,
    );
    let name = device.name().context("TUN name")?;
    eprintln!(
        "TUN up: {name} ({}/{}, mtu {}) — add routes into it to proxy traffic, e.g.\n  \
         sudo route -n add -net <dest> -interface {name}",
        cli.tun_addr, cli.tun_prefix, cli.mtu,
    );

    let netstack = tunnel::Config {
        address: cli.tun_addr,
        prefix: cli.tun_prefix,
        mtu: usize::from(cli.mtu),
    };
    tunnel::run(device, Arc::new(client), netstack).await
}

/// Parse the link and build the client config (blocking: resolves the server).
fn build_config(url: &str) -> Result<Config> {
    let profile =
        config::parse_uri(url).ok_or_else(|| anyhow!("not a hysteria2:// link: {url}"))?;
    Config::from_profile(&profile).context("build client config from link")
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn cli_parses_defaults() -> Result<()> {
        let cli = Cli::try_parse_from(["tun-bridge", "--url", "hysteria2://a@h:443/"])?;
        assert_eq!(cli.tun_addr, Ipv4Addr::new(10, 0, 0, 1), "default TUN addr");
        assert_eq!(cli.tun_prefix, 24, "default prefix");
        assert_eq!(cli.mtu, 1500, "default MTU");
        Ok(())
    }

    #[test]
    fn build_config_rejects_non_link() {
        assert!(
            build_config("https://example.com/").is_err(),
            "non-hysteria URL rejected"
        );
    }
}
