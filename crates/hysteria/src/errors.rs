//! Error types returned by the client and protocol layers.
//!
//! Port of `core/errors/errors.go` from the reference Hysteria 2
//! implementation, kept 1:1 with the Go source (one type per Go struct, same
//! `Display` text) so upstream changes map across directly. `ProtocolError`
//! additionally converts into `std::io::Error` so the byte-parsing helpers in
//! `internal::protocol` can return a single `io::Result`.

use std::error::Error;
use std::fmt;
use std::io;

/// A boxed source error, mirroring Go's `error` interface field.
type BoxError = Box<dyn Error + Send + Sync>;

/// Returned when a configuration field is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub field: String,
    pub reason: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid config: {}: {}", self.field, self.reason)
    }
}

impl Error for ConfigError {}

/// Returned when the client fails to connect to the server.
#[derive(Debug)]
pub struct ConnectError {
    pub err: BoxError,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "connect error: {}", self.err)
    }
}

impl Error for ConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.err.as_ref())
    }
}

/// Returned when the client fails to authenticate with the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    pub status_code: i32,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "authentication error, HTTP status code: {}",
            self.status_code
        )
    }
}

impl Error for AuthError {}

/// Returned when the server rejects the client's dial request (TCP or UDP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialError {
    pub message: String,
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dial error: {}", self.message)
    }
}

impl Error for DialError {}

/// Returned when the client attempts to use a closed connection.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub message: String,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol error: {}", self.message)
    }
}

impl Error for ProtocolError {}

impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}
