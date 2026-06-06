//! The parsed Hysteria 2 connection profile (PLAN §5 `profile/`).
//!
//! Pure `serde` data — the leaf that everything connection-related is built
//! from: the `config` crate produces a [`Profile`] from a `hysteria2://` link,
//! `store` persists it, and `hysteria` builds its client config from it. It
//! holds no parser and depends on nothing but `serde`.
//!
//! Scope: the fields a `hysteria2://` link carries (server, auth, TLS, obfs)
//! plus `fast_open`. Bandwidth and QUIC tuning are config-file-only in the
//! reference and are deferred to the config-file work (PLAN step 4).

use serde::Deserialize;
use serde::Serialize;

/// A Hysteria 2 connection profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// TLS settings as a link carries them (PLAN §7.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls {
    /// TLS server name (SNI); empty means "derive from the server host".
    #[serde(default)]
    pub sni: String,
    /// Skip CA verification. Only honored together with a pin (PLAN §7.3).
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obfs {
    /// Obfuscation type (e.g. `salamander`).
    #[serde(rename = "type")]
    pub obfs_type: String,
    pub password: String,
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
    fn minimal_profile_deserializes_with_defaults() -> anyhow::Result<()> {
        let profile: Profile = serde_json::from_str(r#"{"server":"host:443"}"#)?;
        assert_eq!(profile.server, "host:443", "server parsed");
        assert_eq!(profile.auth, "", "auth defaults empty");
        assert!(profile.obfs.is_none(), "obfs defaults to none");
        assert!(!profile.fast_open, "fast_open defaults false");
        Ok(())
    }
}
