//! Smoke test for the Node-backed Hysteria 2 server harness: it boots the real
//! reference server and hands back a usable client config. This validates the
//! Rust ↔ script integration ahead of the client implementation; the conformance
//! tests for the client will reuse [`common::HysteriaServer`].

mod common;

use anyhow::Context as _;
use anyhow::Result;
use common::HysteriaServer;
use common::HysteriaServerOptions;
use pretty_assertions::assert_eq;
use pretty_assertions::assert_ne;
use serde_json::json;

// Tests require `node` and `hysteria` on `PATH`, provided by the `mise`
// environment that runs the suite.

#[tokio::test]
async fn server_starts_and_returns_client_config() -> Result<()> {
    let options = HysteriaServerOptions::default().with_config(json!({
        "auth": { "type": "password", "password": "test-password" },
        "obfs": { "type": "salamander", "salamander": { "password": "obfs-password" } },
    }));
    let server = HysteriaServer::serve(options).await?;
    let config = server.config();

    assert_eq!(config.auth, "test-password", "auth password round-trips");
    assert_ne!(config.port, 0, "a listen port was assigned");
    assert_eq!(
        config.server,
        format!("127.0.0.1:{}", config.port),
        "loopback server address"
    );
    assert_eq!(config.sni, "localhost", "SNI matches the generated cert");
    assert!(config.ca_cert_path.is_file(), "cert PEM path was returned");
    assert!(
        config.url.starts_with("hysteria2://"),
        "client URL is a hysteria2 link: {}",
        config.url,
    );

    let obfs = config
        .obfs
        .as_ref()
        .context("obfs config should be present")?;
    assert_eq!(obfs.r#type, "salamander", "obfs type round-trips");
    assert_eq!(obfs.password, "obfs-password", "obfs password round-trips");

    Ok(())
}

#[tokio::test]
async fn server_defaults_to_no_obfs_and_random_auth() -> Result<()> {
    let server = HysteriaServer::serve(HysteriaServerOptions::default()).await?;
    let config = server.config();

    assert!(config.obfs.is_none(), "no obfs unless configured");
    assert!(
        !config.auth.is_empty(),
        "a random auth password is generated"
    );
    Ok(())
}
