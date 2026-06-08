//! The connect-error enum: the single, secret-free diagnostic channel for the
//! tunnel.
//!
//! A leaf crate (only `thiserror`, a build-time derive). The privileged
//! tunnel/extension — which must not link the app's `model` crate — produces a
//! [`ConnError`] on connect
//! failure and relays it up; both `hysteria`/`tunnel` and `model` depend on this
//! crate, neither on the other. It carries no server address or other secret, so
//! it is safe to cross the FFI boundary, where it is
//! [mapped to an int](ConnError::code). The app turns it into one actionable UI
//! sentence.
//!
//! ```
//! use conn_error::ConnError;
//!
//! // Stable integer codes round-trip across the C ABI; unknown codes are safe.
//! assert_eq!(ConnError::from_code(ConnError::Timeout.code()), ConnError::Timeout);
//! assert_eq!(ConnError::from_code(999), ConnError::Unknown);
//! ```

/// A categorized, secret-free reason a connection attempt failed.
///
/// The integer values are a stable wire contract (the FFI diagnostic code) and
/// must not be renumbered; add new variants with new codes instead. The
/// `#[error]` strings are short, stable, secret-free descriptions (for
/// logs/tests); the user-facing sentence is `model`'s responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, thiserror::Error)]
#[repr(i32)]
pub enum ConnError {
    /// Catch-all / unmapped failure. Also the default and the fallback for any
    /// unrecognized [`code`](ConnError::from_code).
    #[default]
    #[error("unknown error")]
    Unknown = 0,
    /// The server rejected our credentials.
    #[error("authentication failed")]
    AuthFailed = 1,
    /// The server could not be reached (DNS/route/refused). Also covers a
    /// rejected server certificate, which the QUIC layer does not surface
    /// separately. Code 3 is retired (was the cert-pin mismatch).
    #[error("server unreachable")]
    ServerUnreachable = 2,
    /// The connection attempt timed out.
    #[error("connection timed out")]
    Timeout = 4,
}

impl ConnError {
    /// The stable integer code relayed across the C ABI.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Recover a [`ConnError`] from its [`code`](ConnError::code); any
    /// unrecognized value maps to [`ConnError::Unknown`].
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            1 => Self::AuthFailed,
            2 => Self::ServerUnreachable,
            4 => Self::Timeout,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const ALL: [ConnError; 4] = [
        ConnError::Unknown,
        ConnError::AuthFailed,
        ConnError::ServerUnreachable,
        ConnError::Timeout,
    ];

    #[test]
    fn code_roundtrips_for_every_variant() {
        for err in ALL {
            assert_eq!(
                ConnError::from_code(err.code()),
                err,
                "code round-trips: {err}"
            );
        }
    }

    #[test]
    fn unrecognized_codes_map_to_unknown() {
        for code in [-1, 3, 5, 42, i32::MAX, i32::MIN] {
            assert_eq!(
                ConnError::from_code(code),
                ConnError::Unknown,
                "unrecognized code {code} maps to Unknown",
            );
        }
    }

    #[test]
    fn codes_are_the_stable_contract() {
        // Pin the wire values so a renumbering is caught.
        assert_eq!(ConnError::Unknown.code(), 0, "Unknown code");
        assert_eq!(ConnError::AuthFailed.code(), 1, "AuthFailed code");
        assert_eq!(
            ConnError::ServerUnreachable.code(),
            2,
            "ServerUnreachable code"
        );
        assert_eq!(ConnError::Timeout.code(), 4, "Timeout code (3 retired)");
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(
            ConnError::default(),
            ConnError::Unknown,
            "default is Unknown"
        );
    }

    #[test]
    fn display_strings_are_stable() {
        assert_eq!(ConnError::Unknown.to_string(), "unknown error", "Unknown");
        assert_eq!(
            ConnError::AuthFailed.to_string(),
            "authentication failed",
            "AuthFailed"
        );
        assert_eq!(
            ConnError::ServerUnreachable.to_string(),
            "server unreachable",
            "ServerUnreachable"
        );
        assert_eq!(
            ConnError::Timeout.to_string(),
            "connection timed out",
            "Timeout"
        );
    }
}
