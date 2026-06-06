//! Port of `core/internal/protocol/*`: the Hysteria wire framing (TCP proxy
//! requests/responses, UDP messages), HTTP/3 auth headers, padding, and the
//! QUIC varint codec they share. The layout mirrors the Go package
//! file-for-file so upstream updates port directly.

mod http;
mod padding;
mod proxy;
mod varint;

pub use http::*;
pub use proxy::*;
