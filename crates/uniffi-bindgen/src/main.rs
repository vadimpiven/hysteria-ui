//! The `uniffi-bindgen` CLI, pinned to this workspace's `uniffi` version.
//!
//! `UniFFI`'s library-mode generator must match the version whose scaffolding the
//! FFI crates embed, so we build it in-tree rather than installing a loose
//! binary. Dev tool only; never shipped. It produces `bindings/` (gitignored);
//! the Gradle build regenerates them at build time. To generate manually:
//!
//! ```text
//! cargo build -p ffi-app
//! cargo run -p uniffi-bindgen -- generate \
//!     --library target/debug/libffi_app.dylib --language kotlin \
//!     --out-dir bindings/kotlin --no-format
//! ```

fn main() {
    uniffi::uniffi_bindgen_main();
}
