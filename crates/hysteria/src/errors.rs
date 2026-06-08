//! Error types returned by the client and protocol layers.
//!
//! Port of `core/errors/errors.go` from the reference Hysteria 2
//! implementation, kept 1:1 with the Go source (one type per Go struct, same
//! `Display` text) so upstream changes map across directly. `Display`/`Error`
//! are derived with `thiserror`; `ProtocolError` additionally converts into
//! `std::io::Error` so the byte-parsing helpers in `internal::protocol` can
//! return a single `io::Result`.

use std::error::Error;
use std::fmt;
use std::io;

/// A boxed source error, mirroring Go's `error` interface field.
type BoxError = Box<dyn Error + Send + Sync>;

/// Returned when a configuration field is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid config: {field}: {reason}")]
pub struct ConfigError {
    pub field: String,
    pub reason: String,
}

/// Returned when the client fails to connect to the server.
#[derive(Debug, thiserror::Error)]
#[error("connect error: {err}")]
pub struct ConnectError {
    #[source]
    pub err: BoxError,
}

/// Returned when the client fails to authenticate with the server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("authentication error, HTTP status code: {status_code}")]
pub struct AuthError {
    pub status_code: i32,
}

/// Returned when the server rejects the client's dial request (TCP or UDP).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("dial error: {message}")]
pub struct DialError {
    pub message: String,
}

/// Returned when the client attempts to use a closed connection. Hand-written:
/// the cause is optional (Go's `Err error`, which can be nil) and the message is
/// conditional on it, which `thiserror` cannot express.
#[derive(Debug, Default)]
pub struct ClosedError {
    /// The cause, if any (Go's `Err error` field, which can be nil).
    pub err: Option<BoxError>,
}

impl fmt::Display for ClosedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.err {
            None => write!(f, "connection closed"),
            Some(err) => write!(f, "connection closed: {err}"),
        }
    }
}

impl Error for ClosedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.err
            .as_ref()
            .map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

/// Returned when the server/client runs into an unexpected or malformed
/// request/response/message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("protocol error: {message}")]
pub struct ProtocolError {
    pub message: String,
}

impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}
