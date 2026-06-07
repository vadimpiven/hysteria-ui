//! The parsed Hysteria 2 connection profile.
//!
//! Pure `serde` data — the leaf that everything connection-related is built
//! from: the `config` crate produces a [`Profile`] from a `hysteria2://` link,
//! `store` persists it, and `hysteria` builds its client config from it. It
//! holds no parser and depends on nothing but `serde`.
//!
//! Scope: the fields a `hysteria2://` link carries (server, auth, TLS, obfs)
//! plus `fast_open`. Bandwidth and QUIC tuning are not link-carryable (they are
//! config-file-only in the reference), so they are not modeled here.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// A Hysteria 2 connection profile.
///
/// `Debug` is hand-written to redact the bearer credential: a stray `{:?}` (a
/// log line, a panic message) must never leak `auth`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Server address: `host`, `host:port`, or `host:port-range[,port…]` — the
    /// trailing port spec (a range or list) selects port hopping.
    pub server: String,
    /// Authentication credential (the link's userinfo); may be `user:pass`.
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub tls: Tls,
    /// Obfuscation; `None` disables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Obfs>,
    /// Send the proxy request without waiting for the server's response.
    #[serde(default)]
    pub fast_open: bool,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("server", &self.server)
            .field("auth", &"<redacted>")
            .field("tls", &self.tls)
            .field("obfs", &self.obfs)
            .field("fast_open", &self.fast_open)
            .finish()
    }
}

/// TLS settings as a `hysteria2://` link carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls {
    /// TLS server name (SNI); empty means "derive from the server host".
    #[serde(default)]
    pub sni: String,
    /// Skip CA verification. Must be paired with a pin: the client rejects an
    /// `insecure` profile that has no `pin_sha256` rather than connecting blind.
    #[serde(default)]
    pub insecure: bool,
    /// SHA-256 of the server's end-entity certificate (the `pinSHA256` param),
    /// as hex (separators and case are normalized downstream).
    #[serde(default, rename = "pinSHA256", skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<String>,
    /// Custom CA certificate (a config-file path/PEM); a link cannot carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

/// Obfuscation settings. The reference defines `salamander` and `gecko`; only
/// `salamander` is implemented in this client.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obfs {
    /// Obfuscation type (e.g. `salamander`).
    #[serde(rename = "type")]
    pub obfs_type: String,
    pub password: String,
}

impl fmt::Debug for Obfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `password` is the obfuscation pre-shared key — redact it.
        f.debug_struct("Obfs")
            .field("obfs_type", &self.obfs_type)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn profile_json_round_trips() -> anyhow::Result<()> {
        let profile = Profile {
            server: "example.com:443".into(),
            auth: "secret".into(),
            tls: Tls {
                sni: "real.example.com".into(),
                insecure: true,
                pin_sha256: Some("deadbeef".into()),
                ca: None,
            },
            obfs: Some(Obfs {
                obfs_type: "salamander".into(),
                password: "pw".into(),
            }),
            fast_open: true,
        };
        let json = serde_json::to_string(&profile)?;
        let back: Profile = serde_json::from_str(&json)?;
        assert_eq!(back, profile, "Profile round-trips through JSON");
        Ok(())
    }

    #[test]
    fn debug_redacts_secrets() {
        let profile = Profile {
            server: "example.com:443".into(),
            auth: "super-secret-token".into(),
            obfs: Some(Obfs {
                obfs_type: "salamander".into(),
                password: "psk-secret".into(),
            }),
            ..Profile::default()
        };
        let rendered = format!("{profile:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "Debug must not leak the auth credential: {rendered}"
        );
        assert!(
            !rendered.contains("psk-secret"),
            "Debug must not leak the obfs PSK: {rendered}"
        );
        assert!(
            rendered.contains("example.com:443"),
            "non-secret fields still render: {rendered}"
        );
    }

    #[test]
    fn minimal_profile_deserializes_with_defaults() -> anyhow::Result<()> {
        let profile: Profile = serde_json::from_str(r#"{"server":"host:443"}"#)?;
        assert_eq!(profile.server, "host:443", "server parsed");
        assert_eq!(profile.auth, "", "auth defaults empty");
        assert!(profile.obfs.is_none(), "obfs defaults to none");
        assert!(!profile.fast_open, "fast_open defaults false");
        Ok(())
    }
}
