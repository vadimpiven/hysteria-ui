//! The `uniffi-bindgen` CLI, pinned to this workspace's `uniffi` version.
//!
//! `UniFFI`'s library-mode generator must match the version whose scaffolding the
//! FFI crates embed, so we build it in-tree rather than installing a loose
//! binary. Dev tool only; never shipped. Driven by the `gen:kotlin` mise task:
//! `uniffi-bindgen generate --library <cdylib> --language kotlin --out-dir …`.

fn main() {
    uniffi::uniffi_bindgen_main();
}
