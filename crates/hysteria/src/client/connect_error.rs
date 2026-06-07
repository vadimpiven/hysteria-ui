//! The categorized result of a failed [`connect`](super::Client::connect).
//!
//! `connect` keeps the full cause chain for logs while tagging each failure with
//! the category a caller branches on. The tag maps to a secret-free [`ConnError`]
//! (no server address or other secret travels with it) that the app turns into
//! one actionable sentence; the attached cause is for diagnostics only.

use std::error::Error;
use std::fmt;

use conn_error::ConnError;

/// Why a connection attempt failed, with the underlying cause attached.
#[derive(Debug)]
pub enum ConnectFailure {
    /// The profile was unusable (normally rejected when the link is saved).
    Config(anyhow::Error),
    /// The server could not be reached, or the handshake failed short of a
    /// timeout or a pin mismatch (refused, no route, reset, protocol error).
    Unreachable(anyhow::Error),
    /// The QUIC handshake timed out.
    Timeout(anyhow::Error),
    /// The server's certificate did not match the link's pinned `pinSHA256`.
    PinMismatch(anyhow::Error),
    /// The server rejected our credentials.
    Auth(anyhow::Error),
}

impl ConnectFailure {
    /// The underlying cause, for diagnostics.
    fn cause(&self) -> &anyhow::Error {
        match self {
            Self::Config(e)
            | Self::Unreachable(e)
            | Self::Timeout(e)
            | Self::PinMismatch(e)
            | Self::Auth(e) => e,
        }
    }
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Config(_) => "invalid configuration",
            Self::Unreachable(_) => "server unreachable",
            Self::Timeout(_) => "connection timed out",
            Self::PinMismatch(_) => "server certificate pin mismatch",
            Self::Auth(_) => "authentication failed",
        };
        // `{:#}` renders the cause's full chain inline (this type exposes no
        // `source`, so the whole story lives in the message).
        write!(f, "{label}: {:#}", self.cause())
    }
}

impl Error for ConnectFailure {}

/// Map a failure to its secret-free wire category for the app/extension wall.
impl From<&ConnectFailure> for ConnError {
    fn from(failure: &ConnectFailure) -> Self {
        match failure {
            ConnectFailure::Config(_) => ConnError::Unknown,
            ConnectFailure::Unreachable(_) => ConnError::ServerUnreachable,
            ConnectFailure::Timeout(_) => ConnError::Timeout,
            ConnectFailure::PinMismatch(_) => ConnError::TlsPinMismatch,
            ConnectFailure::Auth(_) => ConnError::AuthFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn each_category_maps_to_its_conn_error() {
        let cases = [
            (ConnectFailure::Config(anyhow!("x")), ConnError::Unknown),
            (
                ConnectFailure::Unreachable(anyhow!("x")),
                ConnError::ServerUnreachable,
            ),
            (ConnectFailure::Timeout(anyhow!("x")), ConnError::Timeout),
            (
                ConnectFailure::PinMismatch(anyhow!("x")),
                ConnError::TlsPinMismatch,
            ),
            (ConnectFailure::Auth(anyhow!("x")), ConnError::AuthFailed),
        ];
        for (failure, expected) in &cases {
            assert_eq!(ConnError::from(failure), *expected, "{failure}");
        }
    }

    #[test]
    fn display_carries_the_category_and_cause() {
        let failure = ConnectFailure::Timeout(anyhow!("idle for 5s"));
        assert_eq!(
            failure.to_string(),
            "connection timed out: idle for 5s",
            "category label plus cause"
        );
    }
}
