//! Random framing padding.
//!
//! Port of `core/internal/protocol/padding.go`. Go uses `math/rand`; we use the
//! `rand` crate. Padding is anti-probing filler, not a security primitive.

use rand::Rng as _;

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A half-open padding length range `[min, max)`.
pub struct Padding {
    pub min: usize,
    pub max: usize,
}

impl Padding {
    /// A fresh random padding string whose length is in `[min, max)`.
    #[must_use]
    pub fn string(&self) -> String {
        let mut rng = rand::rng();
        let n = self.min + rng.random_range(0..self.max - self.min);
        let mut bytes = vec![0u8; n];
        for byte in &mut bytes {
            *byte = PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())];
        }
        // PADDING_CHARS is ASCII, so this is lossless.
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

// Client-only: the `*_RESPONSE_PADDING` ranges from padding.go are server-side.
pub(crate) const AUTH_REQUEST_PADDING: Padding = Padding {
    min: 256,
    max: 2048,
};
pub(crate) const TCP_REQUEST_PADDING: Padding = Padding { min: 64, max: 512 };
