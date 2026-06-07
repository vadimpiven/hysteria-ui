//! The categorized result of a failed [`connect`](super::Client::connect).
//!
//! `connect` keeps the full cause chain for logs while tagging each failure with
//! the category a caller branches on. The tag maps to a secret-free [`ConnError`]
//! (no server address or other secret travels with it) that the app turns into
//! one actionable sentence; the attached cause is for diagnostics only.

use conn_error::ConnError;

/// Why a connection attempt failed, with the underlying cause attached. The
/// `{0:#}` in each message renders the cause's full chain inline; the type
/// exposes no `source` (anyhow's `Error` is not a `std::error::Error`), so the
/// whole story lives in the message.
#[derive(Debug, thiserror::Error)]
pub enum ConnectFailure {
    /// The profile was unusable (normally rejected when the link is saved).
    #[error("invalid configuration: {0:#}")]
    Config(anyhow::Error),
    /// The server could not be reached, or the handshake failed short of a
    /// timeout (refused, no route, reset, untrusted certificate, protocol
    /// error). A rejected certificate is not separable here — the QUIC layer
    /// flattens the reason into a TLS alert.
    #[error("server unreachable: {0:#}")]
    Unreachable(anyhow::Error),
    /// The QUIC handshake timed out.
    #[error("connection timed out: {0:#}")]
    Timeout(anyhow::Error),
    /// The server rejected our credentials.
    #[error("authentication failed: {0:#}")]
    Auth(anyhow::Error),
}

/// Map a failure to its secret-free wire category for the app/extension wall.
impl From<&ConnectFailure> for ConnError {
    fn from(failure: &ConnectFailure) -> Self {
        match failure {
            ConnectFailure::Config(_) => ConnError::Unknown,
            ConnectFailure::Unreachable(_) => ConnError::ServerUnreachable,
            ConnectFailure::Timeout(_) => ConnError::Timeout,
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
