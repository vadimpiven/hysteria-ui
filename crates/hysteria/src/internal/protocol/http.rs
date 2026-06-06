//! HTTP/3 authentication handshake headers.
//!
//! Port of `core/internal/protocol/http.go`. Go reads/writes a `net/http.Header`
//! map; we abstract that as the [`Header`] trait so the `h3` layer (the client
//! implements it for `http::HeaderMap`) — or any header container — can carry the
//! handshake.
//!
//! Client-only: the server-side counterparts (`AuthRequestFromHeader`,
//! `AuthResponseToHeader`) are intentionally omitted.

use super::padding;

pub const URL_HOST: &str = "hysteria";
pub const URL_PATH: &str = "/auth";

pub const REQUEST_HEADER_AUTH: &str = "Hysteria-Auth";
pub const RESPONSE_HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
pub const COMMON_HEADER_CC_RX: &str = "Hysteria-CC-RX";
pub const COMMON_HEADER_PADDING: &str = "Hysteria-Padding";

pub const STATUS_AUTH_OK: u16 = 233;

/// What the client sends to the server for authentication.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    pub auth: String,
    /// 0 = unknown, client asks server to use bandwidth detection.
    pub rx: u64,
}

/// What the server sends to the client when authentication passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    /// 0 = unlimited.
    pub rx: u64,
    /// true = server asks client to use bandwidth detection.
    pub rx_auto: bool,
}

/// A minimal view of an HTTP header map (`net/http.Header`): first value by key.
pub trait Header {
    fn get(&self, key: &str) -> Option<&str>;
    fn set(&mut self, key: &str, value: String);
}

pub fn auth_request_to_header(h: &mut impl Header, req: &AuthRequest) {
    h.set(REQUEST_HEADER_AUTH, req.auth.clone());
    h.set(COMMON_HEADER_CC_RX, req.rx.to_string());
    h.set(
        COMMON_HEADER_PADDING,
        padding::AUTH_REQUEST_PADDING.string(),
    );
}

/// Go's `strconv.ParseBool`: true for `1`/`t`/`T`/`TRUE`/`true`/`True`; anything
/// else (including unparsable values, whose error Go discards) is false.
fn parse_bool(s: &str) -> bool {
    matches!(s, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

#[must_use]
pub fn auth_response_from_header(h: &impl Header) -> AuthResponse {
    let udp_enabled = h.get(RESPONSE_HEADER_UDP_ENABLED).is_some_and(parse_bool);
    let rx_str = h.get(COMMON_HEADER_CC_RX).unwrap_or_default();
    if rx_str == "auto" {
        // Special case for server requesting client to use bandwidth detection.
        AuthResponse {
            udp_enabled,
            rx: 0,
            rx_auto: true,
        }
    } else {
        AuthResponse {
            udp_enabled,
            rx: rx_str.parse().unwrap_or(0),
            rx_auto: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::hash::BuildHasher;

    use pretty_assertions::assert_eq;

    use super::*;

    // A simple `Header` backing for the round-trip tests. The real client
    // implements `Header` for `http::HeaderMap`.
    impl<S: BuildHasher> Header for HashMap<String, String, S> {
        fn get(&self, key: &str) -> Option<&str> {
            HashMap::get(self, key).map(String::as_str)
        }

        fn set(&mut self, key: &str, value: String) {
            self.insert(key.to_string(), value);
        }
    }

    #[test]
    fn auth_request_to_header_sets_fields_and_pads() {
        let mut h = HashMap::new();
        auth_request_to_header(
            &mut h,
            &AuthRequest {
                auth: "secret-token".into(),
                rx: 100_000,
            },
        );
        assert_eq!(
            Header::get(&h, REQUEST_HEADER_AUTH),
            Some("secret-token"),
            "auth header"
        );
        assert_eq!(
            Header::get(&h, COMMON_HEADER_CC_RX),
            Some("100000"),
            "rx header"
        );
        assert!(
            Header::get(&h, COMMON_HEADER_PADDING).is_some_and(|p| p.len() >= 256),
            "padding header is present and within range",
        );
    }

    #[test]
    fn auth_response_from_header_parses() {
        let mut h = HashMap::new();
        h.set(RESPONSE_HEADER_UDP_ENABLED, "true".into());
        h.set(COMMON_HEADER_CC_RX, "42".into());
        assert_eq!(
            auth_response_from_header(&h),
            AuthResponse {
                udp_enabled: true,
                rx: 42,
                rx_auto: false,
            },
            "response headers parse",
        );
    }

    #[test]
    fn auth_response_from_header_parses_bool_variants() {
        // Go's strconv.ParseBool accepts more than the literal "true".
        for truthy in ["1", "t", "T", "TRUE", "true", "True"] {
            let mut h = HashMap::new();
            h.set(RESPONSE_HEADER_UDP_ENABLED, truthy.into());
            assert!(
                auth_response_from_header(&h).udp_enabled,
                "{truthy:?} parses as UDP enabled",
            );
        }
        for falsy in ["0", "false", "no", "", "yes"] {
            let mut h = HashMap::new();
            h.set(RESPONSE_HEADER_UDP_ENABLED, falsy.into());
            assert!(
                !auth_response_from_header(&h).udp_enabled,
                "{falsy:?} parses as UDP disabled",
            );
        }
        // Missing header ⇒ disabled.
        assert!(
            !auth_response_from_header(&HashMap::new()).udp_enabled,
            "missing UDP header ⇒ disabled",
        );
    }

    #[test]
    fn auth_response_from_header_rx_auto() {
        // The server requests bandwidth detection with the literal "auto".
        let mut h = HashMap::new();
        h.set(COMMON_HEADER_CC_RX, "auto".into());
        assert_eq!(
            auth_response_from_header(&h),
            AuthResponse {
                udp_enabled: false,
                rx: 0,
                rx_auto: true,
            },
            "auto parses to rx_auto",
        );
    }
}
