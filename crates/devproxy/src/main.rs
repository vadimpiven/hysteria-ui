//! `devproxy` — a dev-only SOCKS5 proxy over the Hysteria 2 client.
//!
//! Thin entry point: parse args and hand off to the (tested) library. See
//! `devproxy --help` for usage.

use clap::Parser as _;
use devproxy::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    devproxy::run(Cli::parse()).await
}
