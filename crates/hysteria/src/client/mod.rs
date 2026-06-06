//! Port of `core/client/*`: the Hysteria 2 client — connection setup, the TCP
//! relay, the UDP session manager, and authentication over the Quinn transport.

pub mod config;
// Pure internals (socket wrappers + TLS pinning); not part of the public API.
mod hop_socket;
mod obfs_socket;
mod tls;
pub mod transport;
pub mod udp;

pub use transport::Client;
pub use transport::HandshakeInfo;
pub use transport::TcpConn;
