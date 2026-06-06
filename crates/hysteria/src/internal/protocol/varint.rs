//! QUIC variable-length integer codec (RFC 9000 §16).
//!
//! The Go protocol code relies on `quic-go`'s `quicvarint` package for `Len`
//! and `Read`, plus a local `varintPut` in `proxy.go`. Both are reproduced here
//! so the rest of the port stays dependency-free and matches the wire format
//! byte-for-byte.

use std::io;

const MAX_VAR_INT1: u64 = 63;
const MAX_VAR_INT2: u64 = 16383;
const MAX_VAR_INT4: u64 = 1_073_741_823;
const MAX_VAR_INT8: u64 = 4_611_686_018_427_387_903;

/// Number of bytes the varint encoding of `i` occupies (`quicvarint.Len`).
#[must_use]
pub const fn len(i: u64) -> usize {
    if i <= MAX_VAR_INT1 {
        1
    } else if i <= MAX_VAR_INT2 {
        2
    } else if i <= MAX_VAR_INT4 {
        4
    } else {
        // Values above maxVarInt8 cannot occur for any length/ID we encode;
        // `quicvarint.Len` would panic, we report the widest encoding instead.
        8
    }
}

/// Write the varint encoding of `i` into the front of `b`, returning the number
/// of bytes written. Port of `varintPut` from `proxy.go`.
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the masking/shifting is the varint encoding"
)]
pub fn put(b: &mut [u8], i: u64) -> usize {
    if i <= MAX_VAR_INT1 {
        b[0] = i as u8;
        1
    } else if i <= MAX_VAR_INT2 {
        b[0] = (i >> 8) as u8 | 0x40;
        b[1] = i as u8;
        2
    } else if i <= MAX_VAR_INT4 {
        b[0] = (i >> 24) as u8 | 0x80;
        b[1] = (i >> 16) as u8;
        b[2] = (i >> 8) as u8;
        b[3] = i as u8;
        4
    } else if i <= MAX_VAR_INT8 {
        b[0] = (i >> 56) as u8 | 0xc0;
        b[1] = (i >> 48) as u8;
        b[2] = (i >> 40) as u8;
        b[3] = (i >> 32) as u8;
        b[4] = (i >> 24) as u8;
        b[5] = (i >> 16) as u8;
        b[6] = (i >> 8) as u8;
        b[7] = i as u8;
        8
    } else {
        unreachable!("{i:#x} doesn't fit into 62 bits")
    }
}

/// Read a varint from `r` (`quicvarint.Read`). The two most-significant bits of
/// the first byte select the 1/2/4/8-byte length; the remaining bits are the
/// value's high bits.
pub fn read<R: io::Read>(r: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let length = 1usize << ((first[0] & 0xc0) >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    let mut byte = [0u8; 1];
    for _ in 1..length {
        r.read_exact(&mut byte)?;
        value = (value << 8) | u64::from(byte[0]);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn len_matches_the_encoding_boundaries() {
        assert_eq!(len(0), 1, "0 ⇒ 1 byte");
        assert_eq!(len(MAX_VAR_INT1), 1, "2^6-1 ⇒ 1 byte");
        assert_eq!(len(MAX_VAR_INT1 + 1), 2, "2^6 ⇒ 2 bytes");
        assert_eq!(len(MAX_VAR_INT2), 2, "2^14-1 ⇒ 2 bytes");
        assert_eq!(len(MAX_VAR_INT2 + 1), 4, "2^14 ⇒ 4 bytes");
        assert_eq!(len(MAX_VAR_INT4), 4, "2^30-1 ⇒ 4 bytes");
        assert_eq!(len(MAX_VAR_INT4 + 1), 8, "2^30 ⇒ 8 bytes");
        assert_eq!(len(MAX_VAR_INT8), 8, "2^62-1 ⇒ 8 bytes");
    }

    #[test]
    fn put_then_read_round_trips_each_length() -> io::Result<()> {
        let values = [
            0,
            1,
            MAX_VAR_INT1,
            MAX_VAR_INT1 + 1,
            MAX_VAR_INT2,
            MAX_VAR_INT2 + 1,
            MAX_VAR_INT4,
            MAX_VAR_INT4 + 1,
            MAX_VAR_INT8,
        ];
        for v in values {
            let mut buf = [0u8; 8];
            let n = put(&mut buf, v);
            assert_eq!(n, len(v), "put writes len() bytes for {v}");
            let mut cursor = io::Cursor::new(&buf[..n]);
            assert_eq!(read(&mut cursor)?, v, "round-trips {v}");
        }
        Ok(())
    }

    // (encoded bytes, decoded value) — aliased for clippy's type_complexity.
    type SampleVector = (&'static [u8], u64);

    #[test]
    fn read_decodes_rfc9000_sample_vectors() -> io::Result<()> {
        // The worked examples from RFC 9000 §16.
        let cases: &[SampleVector] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15293),
            (&[0x25], 37),
            // 37 also has a (non-minimal) 2-byte encoding that decodes the same.
            (&[0x40, 0x25], 37),
        ];
        for (bytes, want) in cases {
            let mut cursor = io::Cursor::new(*bytes);
            assert_eq!(read(&mut cursor)?, *want, "decodes {bytes:?}");
        }
        Ok(())
    }

    #[test]
    fn read_errors_on_a_short_buffer() {
        assert!(
            read(&mut io::Cursor::new(&[][..])).is_err(),
            "empty input ⇒ error",
        );
        // First byte selects the 4-byte form but only two bytes are present.
        assert!(
            read(&mut io::Cursor::new(&[0x80, 0x01][..])).is_err(),
            "truncated multi-byte ⇒ error",
        );
    }
}
