//! Test helper that boots the reference Hysteria 2 server through the Node
//! harness (`scripts/hysteria-server.ts`), mirroring how pframes-rs drives its
//! `parquet-server.mjs`: read the JSON client config from its single stdout
//! line (the server's logs go to the inherited stderr), and stop the server on
//! drop.
//!
//! Requires `node` and `hysteria` on `PATH` — both provided by `mise`.

// `allow` (not `expect`): this helper is compiled into several integration-test
// binaries, each reading a different subset of fields, so the lint fires in some
// and not others — `expect` would itself warn in the binary that reads them all.
#![allow(
    dead_code,
    reason = "shared harness helper; partial use per test binary"
)]

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt as _;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::ChildStdin;
use tokio::process::Command;

/// Salamander obfuscation, as carried by a `hysteria2://` link.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientObfs {
    pub r#type: String,
    pub password: String,
}

/// Connection info the harness returns for the just-started server. Mirror of
/// the `ClientConfig` interface in `scripts/hysteria-server.ts`, which prints it
/// as the first stdout line — keep the two field sets in sync.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HysteriaClientConfig {
    /// Ready-to-parse `hysteria2://` URI.
    pub url: String,
    /// `host:port` of the server.
    pub server: String,
    pub port: u16,
    /// Bearer auth password.
    pub auth: String,
    /// TLS server name (the cert's CN/SAN).
    pub sni: String,
    /// Path to the self-signed cert (PEM), trusted via the CA path since it is
    /// not publicly rooted.
    pub ca_cert_path: PathBuf,
    /// Present only when the server config enables obfuscation.
    pub obfs: Option<ClientObfs>,
}

/// Options for the spawned Hysteria 2 server.
#[derive(Default)]
pub struct HysteriaServerOptions {
    config: Option<serde_json::Value>,
}

impl HysteriaServerOptions {
    /// Partial Hysteria 2 *server* config (auth, obfs, masquerade, …); merged
    /// into the generated TLS and listen settings. A free port is always chosen.
    #[must_use]
    pub fn with_config(mut self, config: serde_json::Value) -> Self {
        self.config = Some(config);
        self
    }
}

/// A running reference Hysteria 2 server, stopped when dropped.
pub struct HysteriaServer {
    // Held open for the server's lifetime; closing it (on drop, first field) is
    // the graceful-stop signal to the Node harness. Declared before `process`
    // so the EOF is delivered before the child handle is released.
    _stdin: ChildStdin,
    _process: Child,
    config: HysteriaClientConfig,
}

impl HysteriaServer {
    /// Start a server with the given options and wait until it is accepting
    /// connections, returning the matching client config.
    pub async fn serve(options: HysteriaServerOptions) -> Result<Self> {
        let mut script = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        script.extend(["..", "..", "scripts", "hysteria-server.ts"]);

        let mut command = Command::new("node");
        command.arg(&script);
        if let Some(config) = &options.config {
            command.arg("--config").arg(serde_json::to_string(config)?);
        }

        // stdin piped (kept open as the shutdown channel), stdout piped (the one
        // config line), stderr inherited so server logs surface in test output.
        let mut process = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("failed to spawn node scripts/hysteria-server.ts")?;

        let stdin = process.stdin.take().context("child stdin unavailable")?;
        let stdout = process.stdout.take().context("child stdout unavailable")?;
        let mut lines = BufReader::new(stdout).lines();

        let Some(config_line) = lines.next_line().await? else {
            bail!("hysteria-server exited before emitting its client config");
        };
        let config: HysteriaClientConfig = serde_json::from_str(&config_line)
            .with_context(|| format!("invalid client config line: {config_line}"))?;

        Ok(Self {
            _stdin: stdin,
            _process: process,
            config,
        })
    }

    /// The connection info for the running server.
    #[must_use]
    pub fn config(&self) -> &HysteriaClientConfig {
        &self.config
    }
}
