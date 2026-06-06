//! The connect-error enum: the single, secret-free diagnostic channel for the
//! tunnel.
//!
//! A dependency-free leaf crate (PLAN.md §5). The privileged tunnel/extension —
//! which must not link `model` (the app/ext wall, §3.8) — produces a
//! [`ConnError`] on connect failure and relays it up; both `hysteria`/`tunnel`
//! and `model` depend on this crate, neither on the other. It carries no server
//! address or other secret, so it is safe to cross the FFI boundary, where it is
//! [mapped to an int](ConnError::code) (§7.6). `model` turns it into one
//! actionable UI sentence.
//!
//! ```
//! use conn_error::ConnError;
//!
//! // Stable integer codes round-trip across the C ABI; unknown codes are safe.
//! assert_eq!(ConnError::from_code(ConnError::Timeout.code()), ConnError::Timeout);
//! assert_eq!(ConnError::from_code(999), ConnError::Unknown);
//! ```

use std::error::Error;
use std::fmt;

/// A categorized, secret-free reason a connection attempt failed.
///
/// The integer values are a stable wire contract (the FFI diagnostic code) and
/// must not be renumbered; add new variants with new codes instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum ConnError {
    /// Catch-all / unmapped failure. Also the default and the fallback for any
    /// unrecognized [`code`](ConnError::from_code).
    #[default]
    Unknown = 0,
    /// The server rejected our credentials.
    AuthFailed = 1,
    /// The server could not be reached (DNS/route/refused).
    ServerUnreachable = 2,
    /// The server certificate did not match the pinned `pinSHA256` (§7.3).
    TlsPinMismatch = 3,
    /// The connection attempt timed out.
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
            3 => Self::TlsPinMismatch,
            4 => Self::Timeout,
            _ => Self::Unknown,
        }
    }

    /// A short, stable, secret-free description (for logs/tests). The
    /// user-facing sentence is `model`'s responsibility, not this leaf's.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown error",
            Self::AuthFailed => "authentication failed",
            Self::ServerUnreachable => "server unreachable",
            Self::TlsPinMismatch => "TLS certificate pin mismatch",
            Self::Timeout => "connection timed out",
        }
    }
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for ConnError {}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const ALL: [ConnError; 5] = [
        ConnError::Unknown,
        ConnError::AuthFailed,
        ConnError::ServerUnreachable,
        ConnError::TlsPinMismatch,
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
        for code in [-1, 5, 42, i32::MAX, i32::MIN] {
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
        assert_eq!(ConnError::TlsPinMismatch.code(), 3, "TlsPinMismatch code");
        assert_eq!(ConnError::Timeout.code(), 4, "Timeout code");
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
    fn display_matches_as_str() {
        for err in ALL {
            assert_eq!(
                err.to_string(),
                err.as_str(),
                "Display matches as_str: {err}"
            );
        }
    }
}
