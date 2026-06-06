//! Salamander packet obfuscation.
//!
//! Port of `extras/obfs/salamander.go`. Each packet is obfuscated with the
//! BLAKE2b-256 hash of a pre-shared key combined with a random salt. Wire
//! format: `[8-byte salt][payload XOR key]`, where `key = BLAKE2b-256(PSK ∥ salt)`
//! and payload byte `i` is XOR'd with `key[i % 32]`.
//!
//! The Go original shares a key-input buffer and `math/rand` source under a
//! mutex; we instead hash incrementally (no shared buffer) and draw the salt
//! from the `rand` crate, so [`SalamanderObfuscator`] is `Sync` without locking.

use blake2::Blake2b;
use blake2::Digest as _;
use blake2::digest::consts::U32;
use rand::Rng as _;

use crate::errors::ConfigError;

/// `BLAKE2b` with a 32-byte (256-bit) digest, matching Go's `blake2b.Sum256`.
type Blake2b256 = Blake2b<U32>;

const PSK_MIN_LEN: usize = 4;
const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32; // blake2b.Size256

/// Obfuscates/deobfuscates packets with Salamander.
pub struct SalamanderObfuscator {
    psk: Vec<u8>,
}

impl SalamanderObfuscator {
    /// Build an obfuscator from a pre-shared key (≥ 4 bytes).
    pub fn new(psk: &[u8]) -> Result<Self, ConfigError> {
        if psk.len() < PSK_MIN_LEN {
            return Err(ConfigError {
                field: "obfs".into(),
                reason: format!("PSK must be at least {PSK_MIN_LEN} bytes"),
            });
        }
        Ok(Self { psk: psk.to_vec() })
    }

    /// Obfuscate `input` into `out` (`[salt][payload XOR key]`). Returns the
    /// number of bytes written, or 0 if `out` is too small.
    pub fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> usize {
        let out_len = input.len() + SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        let salt: [u8; SALT_LEN] = rand::rng().random();
        out[..SALT_LEN].copy_from_slice(&salt);
        let key = self.key(salt);
        for (i, &c) in input.iter().enumerate() {
            out[i + SALT_LEN] = c ^ key[i % KEY_LEN];
        }
        out_len
    }

    /// Deobfuscate `input` into `out`. Returns the number of bytes written, or 0
    /// if `input` is too short or `out` is too small.
    pub fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> usize {
        if input.len() <= SALT_LEN {
            return 0;
        }
        let out_len = input.len() - SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&input[..SALT_LEN]);
        let key = self.key(salt);
        for (i, &c) in input[SALT_LEN..].iter().enumerate() {
            out[i] = c ^ key[i % KEY_LEN];
        }
        out_len
    }

    /// `BLAKE2b-256(PSK ∥ salt)`.
    fn key(&self, salt: [u8; SALT_LEN]) -> [u8; KEY_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn psk_below_minimum_is_rejected() {
        assert!(
            SalamanderObfuscator::new(b"abc").is_err(),
            "3-byte PSK rejected"
        );
        assert!(
            SalamanderObfuscator::new(b"abcd").is_ok(),
            "4-byte PSK accepted"
        );
    }

    // Port of TestSalamanderObfuscator: obfuscate then deobfuscate round-trips,
    // with the expected length changes, over many pseudo-random inputs.
    #[test]
    fn obfuscate_deobfuscate_roundtrips() -> anyhow::Result<()> {
        let obfs =
            SalamanderObfuscator::new(b"average_password").map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut o_out = vec![0u8; 2048];
        let mut d_out = vec![0u8; 2048];
        for round in 0..1000u32 {
            // Deterministic but varied input; content does not matter.
            let r = round.to_le_bytes()[0];
            let input: Vec<u8> = (0..1200u32).map(|i| i.to_le_bytes()[0] ^ r).collect();

            let n = obfs.obfuscate(&input, &mut o_out);
            assert_eq!(n, input.len() + SALT_LEN, "obfuscated length adds the salt");

            let m = obfs.deobfuscate(&o_out[..n], &mut d_out);
            assert_eq!(m, input.len(), "deobfuscated length drops the salt");
            assert_eq!(&d_out[..m], &input[..], "payload round-trips");
        }
        Ok(())
    }

    #[test]
    fn ciphertext_differs_each_call_via_salt() -> anyhow::Result<()> {
        // The random salt means two obfuscations of the same input differ.
        let obfs =
            SalamanderObfuscator::new(b"average_password").map_err(|e| anyhow::anyhow!("{e}"))?;
        let input = [0u8; 64];
        let mut a = vec![0u8; 2048];
        let mut b = vec![0u8; 2048];
        let na = obfs.obfuscate(&input, &mut a);
        let nb = obfs.obfuscate(&input, &mut b);
        assert!(a[..na] != b[..nb], "salt randomizes the ciphertext");
        Ok(())
    }
}
