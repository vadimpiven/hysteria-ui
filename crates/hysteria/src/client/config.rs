//! Client configuration. Port of `core/client/config.go`.
//!
//! `verify_and_fill` fills unset fields with defaults and rejects invalid
//! values, mirroring the Go original. Differences: `server_addr` is a resolved
//! [`SocketAddr`] (required by construction, so Go's nil check is unneeded), TLS
//! is expressed as our pinning-oriented [`TlsConfig`] (PLAN §7.3) rather than a
//! `crypto/tls.Config`, and congestion control is derived from the bandwidth
//! config by the client (Brutal when a TX bound is known, else BBR) rather than
//! a separate `CongestionConfig` — Reno is not supported.

use std::net::SocketAddr;
use std::net::ToSocketAddrs as _;
use std::time::Duration;

use crate::errors::ConfigError;
// Port-hopping port spec is part of the public config surface.
pub use crate::internal::portunion::PortUnion;
pub use crate::internal::portunion::parse_port_union;

const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8_388_608; // 8MB
const DEFAULT_CONN_RECEIVE_WINDOW: u64 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2; // 20MB
const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(10);
const MIN_RECEIVE_WINDOW: u64 = 16384;
const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

/// Client configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub server_addr: SocketAddr,
    pub auth: String,
    pub tls: TlsConfig,
    pub quic: QuicConfig,
    pub bandwidth: BandwidthConfig,
    pub fast_open: bool,
    /// Salamander obfuscation pre-shared key; `None` disables obfuscation.
    pub obfs: Option<Vec<u8>>,
    /// Port hopping: rotate the destination UDP port across these ports (at
    /// `server_addr`'s IP). `None` disables hopping.
    pub hop_ports: Option<PortUnion>,
    /// How often to hop (only used when `hop_ports` is set).
    pub hop_interval: HopIntervalConfig,
}

impl Config {
    /// Create a config with default QUIC settings for `server_addr`.
    #[must_use]
    pub fn new(server_addr: SocketAddr, auth: String, tls: TlsConfig) -> Self {
        Self {
            server_addr,
            auth,
            tls,
            quic: QuicConfig::default(),
            bandwidth: BandwidthConfig::default(),
            fast_open: false,
            obfs: None,
            hop_ports: None,
            hop_interval: HopIntervalConfig::default(),
        }
    }

    /// Fill unset QUIC fields with defaults and validate. Idempotent in spirit;
    /// safe to call once before connecting.
    pub fn verify_and_fill(&mut self) -> Result<(), ConfigError> {
        fill_window(
            &mut self.quic.initial_stream_receive_window,
            DEFAULT_STREAM_RECEIVE_WINDOW,
            "QUICConfig.InitialStreamReceiveWindow",
        )?;
        fill_window(
            &mut self.quic.max_stream_receive_window,
            DEFAULT_STREAM_RECEIVE_WINDOW,
            "QUICConfig.MaxStreamReceiveWindow",
        )?;
        fill_window(
            &mut self.quic.initial_connection_receive_window,
            DEFAULT_CONN_RECEIVE_WINDOW,
            "QUICConfig.InitialConnectionReceiveWindow",
        )?;
        fill_window(
            &mut self.quic.max_connection_receive_window,
            DEFAULT_CONN_RECEIVE_WINDOW,
            "QUICConfig.MaxConnectionReceiveWindow",
        )?;

        if self.quic.max_idle_timeout.is_zero() {
            self.quic.max_idle_timeout = DEFAULT_MAX_IDLE_TIMEOUT;
        } else if self.quic.max_idle_timeout < Duration::from_secs(4)
            || self.quic.max_idle_timeout > Duration::from_mins(2)
        {
            return Err(ConfigError {
                field: "QUICConfig.MaxIdleTimeout".into(),
                reason: "must be between 4s and 120s".into(),
            });
        }

        if self.quic.keep_alive_period.is_zero() {
            self.quic.keep_alive_period = DEFAULT_KEEP_ALIVE_PERIOD;
        } else if self.quic.keep_alive_period < Duration::from_secs(2)
            || self.quic.keep_alive_period > Duration::from_mins(1)
        {
            return Err(ConfigError {
                field: "QUICConfig.KeepAlivePeriod".into(),
                reason: "must be between 2s and 60s".into(),
            });
        }

        if self.hop_ports.is_some() {
            self.hop_interval = self.hop_interval.normalized()?;
        }

        Ok(())
    }

    /// Build a client config from a parsed [`profile::Profile`] (PLAN: `hysteria`
    /// owns the `&Profile -> client config` builder). Resolves the server
    /// address — a trailing port range/list (e.g. `host:7000-8000,9000`) turns on
    /// port hopping — normalizes and decodes the cert pin, and maps Salamander
    /// obfuscation. SNI defaults to the server host when the link omits it.
    ///
    /// Resolving a hostname performs a blocking DNS lookup; an IP literal does
    /// not. Call it at setup, not on a hot path.
    pub fn from_profile(p: &profile::Profile) -> Result<Self, ConfigError> {
        let (host, port_spec) = split_host_port(&p.server);
        let hop_ports = if port_spec.contains(['-', ',']) {
            Some(parse_port_union(port_spec).ok_or_else(|| ConfigError {
                field: "server".into(),
                reason: "invalid port range".into(),
            })?)
        } else {
            None
        };
        let port = primary_port(port_spec)?;
        let ip = (host, port)
            .to_socket_addrs()
            .map_err(|e| ConfigError {
                field: "server".into(),
                reason: format!("resolve {host}: {e}"),
            })?
            .next()
            .ok_or_else(|| ConfigError {
                field: "server".into(),
                reason: format!("no address for {host}"),
            })?;

        let pin_sha256 = match &p.tls.pin_sha256 {
            Some(pin) => Some(parse_pin(pin)?),
            None => None,
        };
        let obfs = match &p.obfs {
            None => None,
            Some(o) if o.obfs_type.eq_ignore_ascii_case("salamander") => {
                Some(o.password.clone().into_bytes())
            },
            Some(o) => {
                return Err(ConfigError {
                    field: "obfs".into(),
                    reason: format!("unsupported obfs type: {}", o.obfs_type),
                });
            },
        };
        let server_name = if p.tls.sni.is_empty() {
            host.to_string()
        } else {
            p.tls.sni.clone()
        };

        let mut config = Config::new(
            ip,
            p.auth.clone(),
            TlsConfig {
                server_name,
                insecure: p.tls.insecure,
                pin_sha256,
                ca: None,
            },
        );
        config.obfs = obfs;
        config.hop_ports = hop_ports;
        config.fast_open = p.fast_open;
        Ok(config)
    }
}

/// Split `host[:port-spec]` into `(host, port-spec)`, defaulting the port to
/// `443` (port of Go's `parseServerAddrString`). Handles `[ipv6]:port`; a bare
/// (unbracketed) IPv6 literal has no port and resolves with the default.
fn split_host_port(server: &str) -> (&str, &str) {
    if let Some(rest) = server.strip_prefix('[')
        && let Some((host, after)) = rest.split_once(']')
    {
        let spec = after.strip_prefix(':').unwrap_or("");
        return (host, if spec.is_empty() { "443" } else { spec });
    }
    match server.rsplit_once(':') {
        // A colon left in the host half means a bare (unbracketed) IPv6 literal;
        // Go's net.SplitHostPort errors on it and falls back to the default port.
        Some((host, spec)) if !host.is_empty() && !spec.is_empty() && !host.contains(':') => {
            (host, spec)
        },
        _ => (server, "443"),
    }
}

/// The port to actually dial: the first port of the spec (the start of the
/// first range/list entry). Port hopping rotates over the rest.
fn primary_port(spec: &str) -> Result<u16, ConfigError> {
    spec.split(['-', ','])
        .next()
        .unwrap_or(spec)
        .parse()
        .map_err(|_| ConfigError {
            field: "server".into(),
            reason: "invalid port".into(),
        })
}

/// Normalize (lowercase, strip `:`/`-`) and decode a hex SHA-256 cert pin.
fn parse_pin(pin: &str) -> Result<[u8; 32], ConfigError> {
    let hex: String = pin
        .chars()
        .filter(|c| !matches!(c, ':' | '-'))
        .collect::<String>()
        .to_lowercase();
    if hex.len() != 64 {
        return Err(ConfigError {
            field: "pinSHA256".into(),
            reason: "must be a 64-character hex SHA-256".into(),
        });
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ConfigError {
            field: "pinSHA256".into(),
            reason: "invalid hex".into(),
        })?;
    }
    Ok(out)
}

/// Port-hop interval range. Port of udphop's `HopIntervalConfig`.
#[derive(Debug, Clone, Copy)]
pub struct HopIntervalConfig {
    pub min: Duration,
    pub max: Duration,
}

impl Default for HopIntervalConfig {
    fn default() -> Self {
        Self {
            min: DEFAULT_HOP_INTERVAL,
            max: DEFAULT_HOP_INTERVAL,
        }
    }
}

impl HopIntervalConfig {
    /// Fill defaults and validate (port of `HopIntervalConfig.normalized`).
    fn normalized(self) -> Result<Self, ConfigError> {
        if self.min.is_zero() && self.max.is_zero() {
            return Ok(Self::default());
        }
        if self.min.is_zero() || self.max.is_zero() {
            return Err(ConfigError {
                field: "hopInterval".into(),
                reason: "min and max hop interval must both be set".into(),
            });
        }
        if self.min > self.max {
            return Err(ConfigError {
                field: "hopInterval".into(),
                reason: "min hop interval must not be greater than max hop interval".into(),
            });
        }
        if self.min < MIN_HOP_INTERVAL {
            return Err(ConfigError {
                field: "hopInterval".into(),
                reason: "hop interval must be at least 5 seconds".into(),
            });
        }
        Ok(self)
    }
}

/// Apply the Go window rule: 0 ⇒ default, otherwise must be ≥ 16384.
fn fill_window(value: &mut u64, default: u64, field: &str) -> Result<(), ConfigError> {
    if *value == 0 {
        *value = default;
    } else if *value < MIN_RECEIVE_WINDOW {
        return Err(ConfigError {
            field: field.into(),
            reason: "must be at least 16384".into(),
        });
    }
    Ok(())
}

/// TLS settings, expressed as the link carries them (PLAN §7.3): an SNI, the
/// `insecure` flag, an optional cert pin, and an optional custom CA (DER).
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// TLS server name (SNI).
    pub server_name: String,
    /// Skip CA verification. Only honored together with a `pin_sha256`.
    pub insecure: bool,
    /// SHA-256 of the server's end-entity certificate (the `pinSHA256` param).
    pub pin_sha256: Option<[u8; 32]>,
    /// Custom CA certificate (DER) for the CA-trust path.
    pub ca: Option<Vec<u8>>,
}

/// QUIC transport tunables. A zero value means "unset" and is replaced by the
/// default in [`Config::verify_and_fill`], as in Go.
#[derive(Debug, Clone, Default)]
pub struct QuicConfig {
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: Duration,
    pub keep_alive_period: Duration,
    pub disable_path_mtu_discovery: bool,
}

/// Maximum bandwidth the server may use, in bytes per second.
#[derive(Debug, Clone, Copy, Default)]
pub struct BandwidthConfig {
    pub max_tx: u64,
    pub max_rx: u64,
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn config() -> Config {
        Config::new(
            SocketAddr::from(([127, 0, 0, 1], 443)),
            "auth".into(),
            TlsConfig::default(),
        )
    }

    #[test]
    fn defaults_are_filled() -> anyhow::Result<()> {
        let mut c = config();
        c.verify_and_fill()?;
        assert_eq!(
            c.quic.initial_stream_receive_window, 8_388_608,
            "stream window default"
        );
        assert_eq!(
            c.quic.max_connection_receive_window, 20_971_520,
            "conn window default"
        );
        assert_eq!(
            c.quic.max_idle_timeout,
            Duration::from_secs(30),
            "idle default"
        );
        assert_eq!(
            c.quic.keep_alive_period,
            Duration::from_secs(10),
            "keepalive default"
        );
        Ok(())
    }

    #[test]
    fn window_below_minimum_is_rejected() -> anyhow::Result<()> {
        let mut c = config();
        c.quic.initial_stream_receive_window = 1024;
        let Err(err) = c.verify_and_fill() else {
            anyhow::bail!("sub-minimum window should be rejected");
        };
        assert_eq!(
            err.field, "QUICConfig.InitialStreamReceiveWindow",
            "field named"
        );
        Ok(())
    }

    #[test]
    fn idle_timeout_bounds_are_enforced() {
        let mut c = config();
        c.quic.max_idle_timeout = Duration::from_secs(1);
        assert!(c.verify_and_fill().is_err(), "1s idle rejected");

        let mut c = config();
        c.quic.max_idle_timeout = Duration::from_secs(200);
        assert!(c.verify_and_fill().is_err(), "200s idle rejected");

        let mut c = config();
        c.quic.max_idle_timeout = Duration::from_secs(20);
        assert!(c.verify_and_fill().is_ok(), "20s idle accepted");
    }

    #[test]
    fn keep_alive_bounds_are_enforced() {
        let mut c = config();
        c.quic.keep_alive_period = Duration::from_secs(1);
        assert!(c.verify_and_fill().is_err(), "1s keepalive rejected");

        let mut c = config();
        c.quic.keep_alive_period = Duration::from_secs(90);
        assert!(c.verify_and_fill().is_err(), "90s keepalive rejected");
    }

    #[test]
    fn hop_interval_is_validated_only_with_hop_ports() {
        // Zero hop_interval defaults to 30s once hopping is enabled.
        let mut c = config();
        c.hop_ports = parse_port_union("1000-2000");
        c.hop_interval = HopIntervalConfig {
            min: Duration::ZERO,
            max: Duration::ZERO,
        };
        assert!(
            c.verify_and_fill().is_ok(),
            "zero interval fills the default"
        );
        assert_eq!(c.hop_interval.min, DEFAULT_HOP_INTERVAL, "defaulted to 30s");

        // Below the 5s floor is rejected (but only when hopping is on).
        let mut c = config();
        c.hop_ports = parse_port_union("1000-2000");
        c.hop_interval = HopIntervalConfig {
            min: Duration::from_secs(1),
            max: Duration::from_secs(1),
        };
        assert!(c.verify_and_fill().is_err(), "sub-5s interval rejected");

        // Without hop_ports, the interval isn't validated.
        let mut c = config();
        c.hop_interval = HopIntervalConfig {
            min: Duration::from_secs(1),
            max: Duration::from_secs(1),
        };
        assert!(
            c.verify_and_fill().is_ok(),
            "interval ignored without hop_ports"
        );
    }

    #[test]
    fn from_profile_maps_connection_fields() -> anyhow::Result<()> {
        let pin_hex = "ab".repeat(32); // 64 hex chars ⇒ [0xab; 32]
        let p = profile::Profile {
            server: "127.0.0.1:8443".into(),
            auth: "secret".into(),
            tls: profile::Tls {
                sni: "example.com".into(),
                insecure: true,
                pin_sha256: Some(pin_hex),
                ca: None,
            },
            obfs: Some(profile::Obfs {
                obfs_type: "salamander".into(),
                password: "pw".into(),
            }),
            fast_open: true,
        };
        let c = Config::from_profile(&p)?;
        assert_eq!(c.server_addr, "127.0.0.1:8443".parse()?, "server addr");
        assert_eq!(c.auth, "secret", "auth");
        assert_eq!(c.tls.server_name, "example.com", "sni");
        assert!(c.tls.insecure, "insecure");
        assert_eq!(c.tls.pin_sha256, Some([0xab; 32]), "decoded pin");
        assert_eq!(c.obfs, Some(b"pw".to_vec()), "obfs psk");
        assert!(c.fast_open, "fast open");
        assert!(c.hop_ports.is_none(), "single port ⇒ no hopping");
        Ok(())
    }

    #[test]
    fn from_profile_defaults_sni_and_enables_port_hopping() -> anyhow::Result<()> {
        let p = profile::Profile {
            server: "127.0.0.1:8000-8002".into(),
            auth: "a".into(),
            ..Default::default()
        };
        let c = Config::from_profile(&p)?;
        assert_eq!(c.tls.server_name, "127.0.0.1", "sni defaults to host");
        assert_eq!(c.server_addr.port(), 8000, "primary port = range start");
        let Some(hop) = c.hop_ports else {
            anyhow::bail!("port range should enable hopping");
        };
        assert!(hop.contains(8001), "range expands to its ports");
        Ok(())
    }

    #[test]
    fn from_profile_handles_ipv6_hosts() -> anyhow::Result<()> {
        // Bracketed host:port.
        let c = Config::from_profile(&profile::Profile {
            server: "[::1]:8443".into(),
            ..Default::default()
        })?;
        assert_eq!(
            c.server_addr,
            "[::1]:8443".parse()?,
            "bracketed IPv6 host:port"
        );
        assert_eq!(c.tls.server_name, "::1", "sni defaults to IPv6 host");
        // A bare IPv6 literal must not be split on its colons (default port).
        let c = Config::from_profile(&profile::Profile {
            server: "::1".into(),
            ..Default::default()
        })?;
        assert_eq!(
            c.server_addr,
            "[::1]:443".parse()?,
            "bare IPv6 ⇒ default port"
        );
        Ok(())
    }

    #[test]
    fn from_profile_rejects_unsupported_obfs() {
        let p = profile::Profile {
            server: "127.0.0.1:443".into(),
            obfs: Some(profile::Obfs {
                obfs_type: "gecko".into(),
                password: "x".into(),
            }),
            ..Default::default()
        };
        assert!(
            Config::from_profile(&p).is_err(),
            "gecko obfs is not supported",
        );
    }

    #[test]
    fn hop_interval_partial_and_reversed_are_rejected() {
        // Only one bound set ⇒ rejected ("min and max ... must both be set").
        let mut c = config();
        c.hop_ports = parse_port_union("1000-2000");
        c.hop_interval = HopIntervalConfig {
            min: Duration::from_secs(10),
            max: Duration::ZERO,
        };
        assert!(c.verify_and_fill().is_err(), "partial interval rejected");

        // min > max ⇒ rejected.
        let mut c = config();
        c.hop_ports = parse_port_union("1000-2000");
        c.hop_interval = HopIntervalConfig {
            min: Duration::from_secs(30),
            max: Duration::from_secs(10),
        };
        assert!(c.verify_and_fill().is_err(), "reversed interval rejected");
    }
}
