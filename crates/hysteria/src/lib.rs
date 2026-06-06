//! Hysteria2 client.
//!
//! Rust port of the reference Hysteria 2 core (`core/` in the upstream Go
//! repository, pinned at rev `c3a806b`). This crate currently provides the
//! protocol layer ported close to the Go sources so upstream updates map across
//! directly:
//!
//! - [`errors`] — the client/protocol error types (`core/errors`).
//! - `internal::protocol` — TCP proxy and UDP message framing, HTTP/3 auth
//!   headers, padding, and the QUIC varint codec (`core/internal/protocol`).
//! - `internal::frag` — UDP fragmentation and reassembly (`core/internal/frag`).
//! - `internal::congestion::brutal` — Brutal congestion control as a quinn
//!   `congestion::Controller` (`core/internal/congestion/brutal`).
//! - `client::udp` — the UDP session manager (`core/client/udp.go`).
//!
//! The Quinn-based transport, connection setup, and congestion control land on
//! top of this foundation.

pub mod client;
pub mod errors;

// Crate-internal building blocks (mirrors Go's `internal/`): protocol framing,
// fragmentation, congestion, obfuscation, port-union. The pieces consumers need
// are re-exported through `client` (e.g. `client::config::PortUnion`).
mod internal;
