//! `socks5-bridge` — a SOCKS5 front-end over the Hysteria 2 client.
//!
//! Thin entry point: parse args and hand off to the (tested) library. See
//! `socks5-bridge --help` for usage.

use clap::Parser as _;
use socks5_bridge::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    socks5_bridge::run(Cli::parse()).await
}
