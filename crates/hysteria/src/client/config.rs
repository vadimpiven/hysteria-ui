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
