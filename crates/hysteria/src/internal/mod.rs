//! Port of `core/internal/*`: crate-internal protocol building blocks.
//!
//! These are not part of the public API yet; they will be wired up by the
//! Quinn-based client.

pub mod congestion;
pub mod frag;
pub mod obfs;
pub mod portunion;
pub mod protocol;
