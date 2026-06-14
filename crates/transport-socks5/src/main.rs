//! `transport-socks5` — a SOCKS5 front-end over the Hysteria 2 client.
//!
//! Thin entry point: parse args and hand off to the (tested) library. See
//! `transport-socks5 --help` for usage.

use clap::Parser as _;
use transport_socks5::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    transport_socks5::run(Cli::parse()).await
}
