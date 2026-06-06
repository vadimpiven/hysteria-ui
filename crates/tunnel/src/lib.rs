//! Userspace TUN netstack that drives the Hysteria 2 client.
//!
//! Bridges a TUN device (raw IP packets) to the `hysteria` client: a smoltcp
//! netstack accepts each TCP flow to an arbitrary destination, and the relay
//! splices it to [`Client::tcp`], mirroring the Go TUN handler's per-flow copy.
//! Production loads it behind the FFI extension over the OS-provided fd; the
//! `tun-bridge` dev binary drives it over a macOS utun. UDP relay is the next
//! increment.

mod device;
mod stack;
mod tcp;

use std::sync::Arc;

use anyhow::Context as _;
use anyhow::Result;
use hysteria::client::Client;
pub use stack::Config;
use tokio::io::copy_bidirectional;
use tun_rs::AsyncDevice;

/// Run the netstack over `device`, relaying every accepted flow through
/// `client`. Returns when the device errors (the background netstack task ends).
pub async fn run(device: Arc<AsyncDevice>, client: Arc<Client>, config: Config) -> Result<()> {
    let mut flows = stack::start(device, config);
    while let Some(flow) = flows.recv().await {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            // Per-flow errors are local; drop the flow on failure, as Go does.
            let _ = relay_tcp(flow, client).await;
        });
    }
    Ok(())
}

/// Splice one app TCP flow to a Hysteria tunnel to its original destination.
async fn relay_tcp(flow: stack::TcpFlow, client: Arc<Client>) -> Result<()> {
    let mut tunnel = client
        .tcp(&flow.dst.to_string())
        .await
        .context("open tunnel")?;
    let mut app = flow.stream;
    copy_bidirectional(&mut app, &mut tunnel)
        .await
        .context("relay TCP")?;
    Ok(())
}
