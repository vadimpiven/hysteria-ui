//! `tun-bridge` — a dev TUN front-end over the Hysteria 2 client.
//!
//! Thin entry point: parse args and hand off to the (tested) library. Needs root
//! to open the utun and out-of-band routes to steer traffic into it. See
//! `tun-bridge --help` for usage.

use clap::Parser as _;
use tun_bridge::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tun_bridge::run(Cli::parse()).await
}
