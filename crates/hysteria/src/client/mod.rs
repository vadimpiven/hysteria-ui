//! Port of `core/client/*`: the Hysteria 2 client — connection setup, the TCP
//! relay, the UDP session manager, and authentication over the Quinn transport.

pub mod config;
pub mod hop_socket;
pub mod obfs_socket;
pub mod tls;
pub mod transport;
pub mod udp;

pub use transport::Client;
pub use transport::HandshakeInfo;
pub use transport::TcpConn;
