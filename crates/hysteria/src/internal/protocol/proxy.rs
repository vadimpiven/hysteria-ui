//! TCP proxy request/response framing and UDP message (de)serialization.
//!
//! Port of `core/internal/protocol/proxy.go`. Go's `io.Reader`/`io.Writer`
//! become `std::io::Read`/`std::io::Write`; `quicvarint` lives in
//! [`super::varint`]. Functions that mix I/O and protocol errors return
//! `io::Result`, with `ProtocolError` carried through `ErrorKind::InvalidData`.
//!
//! Client-only crate (PLAN §5): the server-side counterparts from `proxy.go`
//! (`ReadTCPRequest`, `WriteTCPResponse`) are intentionally omitted.

use std::io;
use std::io::Read as _;

use super::padding;
use super::varint;
use crate::errors::ProtocolError;

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

// Max length values are for preventing DoS attacks.
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;

pub const MAX_UDP_SIZE: usize = 4096;

/// Read and discard exactly `n` bytes, erroring on early EOF
/// (`io.CopyN(io.Discard, r, n)`).
fn discard_exact<R: io::Read>(r: &mut R, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut r.take(n), &mut io::sink())?;
    if copied < n {
        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
    } else {
        Ok(())
    }
}

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

pub fn write_tcp_request<W: io::Write>(w: &mut W, addr: &str) -> io::Result<()> {
    let padding = padding::TCP_REQUEST_PADDING.string();
    let padding_len = padding.len();
    let addr_len = addr.len();
    let sz = varint::len(FRAME_TYPE_TCP_REQUEST)
        + varint::len(addr_len as u64)
        + addr_len
        + varint::len(padding_len as u64)
        + padding_len;
    let mut buf = vec![0u8; sz];
    let mut i = varint::put(&mut buf, FRAME_TYPE_TCP_REQUEST);
    i += varint::put(&mut buf[i..], addr_len as u64);
    buf[i..i + addr_len].copy_from_slice(addr.as_bytes());
    i += addr_len;
    i += varint::put(&mut buf[i..], padding_len as u64);
    buf[i..i + padding_len].copy_from_slice(padding.as_bytes());
    w.write_all(&buf)
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

pub fn read_tcp_response<R: io::Read>(r: &mut R) -> io::Result<(bool, String)> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status)?;
    let msg_len = varint::read(r)?;
    if msg_len > MAX_MESSAGE_LENGTH as u64 {
        return Err(ProtocolError {
            message: "invalid message length".into(),
        }
        .into());
    }
    // No message is fine.
    let mut msg_buf = Vec::new();
    if msg_len > 0 {
        let msg_len = usize::try_from(msg_len).map_err(|_| ProtocolError {
            message: "invalid message length".into(),
        })?;
        msg_buf = vec![0u8; msg_len];
        r.read_exact(&mut msg_buf)?;
    }
    let padding_len = varint::read(r)?;
    if padding_len > MAX_PADDING_LENGTH as u64 {
        return Err(ProtocolError {
            message: "invalid padding length".into(),
        }
        .into());
    }
    if padding_len > 0 {
        discard_exact(r, padding_len)?;
    }
    let msg = String::from_utf8(msg_buf).map_err(|_| ProtocolError {
        message: "invalid message encoding".into(),
    })?;
    Ok((status[0] == 0, msg))
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    #[must_use]
    pub fn header_size(&self) -> usize {
        let l_addr = self.addr.len();
        4 + 2 + 1 + 1 + varint::len(l_addr as u64) + l_addr
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Serialize into `buf`, returning the number of bytes written, or `None` if
    /// `buf` is too small (Go returns `-1`).
    #[must_use]
    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < self.size() {
            return None;
        }
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.packet_id.to_be_bytes());
        buf[6] = self.frag_id;
        buf[7] = self.frag_count;
        let mut i = varint::put(&mut buf[8..], self.addr.len() as u64);
        buf[8 + i..8 + i + self.addr.len()].copy_from_slice(self.addr.as_bytes());
        i += self.addr.len();
        buf[8 + i..8 + i + self.data.len()].copy_from_slice(&self.data);
        i += self.data.len();
        Some(8 + i)
    }
}

pub fn parse_udp_message(msg: &[u8]) -> io::Result<UdpMessage> {
    let mut cursor = io::Cursor::new(msg);
    let mut header = [0u8; 8];
    cursor.read_exact(&mut header)?;
    let session_id = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let packet_id = u16::from_be_bytes([header[4], header[5]]);
    let frag_id = header[6];
    let frag_count = header[7];
    let l_addr = varint::read(&mut cursor)?;
    if l_addr == 0 || l_addr > MAX_MESSAGE_LENGTH as u64 {
        return Err(ProtocolError {
            message: "invalid address length".into(),
        }
        .into());
    }
    let l_addr = usize::try_from(l_addr).map_err(|_| ProtocolError {
        message: "invalid address length".into(),
    })?;
    let pos = usize::try_from(cursor.position()).map_err(|_| ProtocolError {
        message: "invalid message length".into(),
    })?;
    let rest = &msg[pos..];
    // <= (not <): we expect at least one byte of data after the address.
    if rest.len() <= l_addr {
        return Err(ProtocolError {
            message: "invalid message length".into(),
        }
        .into());
    }
    let addr = String::from_utf8(rest[..l_addr].to_vec()).map_err(|_| ProtocolError {
        message: "invalid address encoding".into(),
    })?;
    let data = rest[l_addr..].to_vec();
    Ok(UdpMessage {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr,
        data,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use anyhow::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    // Named case shapes for the table-driven tests below (the slice element type
    // is otherwise too complex for clippy's `type_complexity` threshold).
    type MalformedCase = (&'static str, &'static [u8]);
    type WriteRequestCase = (&'static str, &'static str, &'static [u8]);
    type ReadResponseCase = (&'static str, &'static [u8], bool, &'static str, bool);

    // Port of TestUDPMessage.
    #[test]
    fn udp_message_serialize_too_small() {
        // Serialize must report failure when the buffer is too small.
        let mut buf = [0u8; 20];
        let msg = UdpMessage {
            session_id: 66,
            packet_id: 77,
            frag_id: 2,
            frag_count: 5,
            addr: "random_addr".into(),
            data: b"random_data".to_vec(),
        };
        assert!(
            msg.serialize(&mut buf).is_none(),
            "serialize() should fail when the buffer is too small",
        );
    }

    #[test]
    fn udp_message_roundtrip_golden() -> Result<()> {
        // "test 1" from the Go suite, with the exact golden wire bytes.
        let msg = UdpMessage {
            session_id: 1,
            packet_id: 1,
            frag_id: 0,
            frag_count: 1,
            addr: "example.com:80".into(),
            data: b"GET /nothing HTTP/1.1\r\n".to_vec(),
        };
        let want: &[u8] = &[
            0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0xe, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x38, 0x30, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x6e, 0x6f,
            0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
            0xd, 0xa,
        ];

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let n = msg.serialize(&mut buf).context("serialize failed")?;
        assert_eq!(&buf[..n], want, "serialize() golden bytes");

        let parsed = parse_udp_message(want).context("parse failed")?;
        assert_eq!(parsed, msg, "parse_udp_message() round-trips");
        Ok(())
    }

    #[test]
    fn udp_message_roundtrip_large() -> Result<()> {
        // "test 2": a long address plus high session/frag values. We assert the
        // serialize/parse inverse rather than transcribing the 380-byte golden
        // array (the exact wire format is anchored by the golden test above).
        let long = "some_random_goofy_ahh_address_which_is_very_long_".repeat(10);
        let msg = UdpMessage {
            session_id: 1_329_655_244,
            packet_id: 62233,
            frag_id: 8,
            frag_count: 19,
            addr: format!("{long}:9000"),
            data: b"God is great, beer is good, and people are crazy.".to_vec(),
        };

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let n = msg.serialize(&mut buf).context("serialize failed")?;
        assert_eq!(n, msg.size(), "serialize() returns the full message size");

        let parsed = parse_udp_message(&buf[..n]).context("parse failed")?;
        assert_eq!(parsed, msg, "parse_udp_message() round-trips");
        Ok(())
    }

    // Port of TestUDPMessageMalformed.
    #[test]
    fn udp_message_malformed() {
        let cases: &[MalformedCase] = &[
            ("empty", &[]),
            ("zeroes 1", &[0, 0, 0, 0]),
            ("zeroes 2", &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (
                "incomplete 1",
                &[0x66, 0xCC, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55],
            ),
            (
                "incomplete 2",
                &[
                    0x66, 0xCC, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x90, 0xAA, 0xBB, 0xCC, 0xDD,
                    0xEE, 0xFF,
                ],
            ),
        ];
        for (name, data) in cases {
            assert!(
                parse_udp_message(data).is_err(),
                "parse_udp_message() should fail on malformed input: {name}",
            );
        }
    }

    // Port of TestWriteTCPRequest.
    #[test]
    fn write_tcp_request_cases() -> Result<()> {
        // Only the prefix is fixed; the rest is random padding.
        let cases: &[WriteRequestCase] = &[
            ("normal 1", "google.com:443", b"\x44\x01\x0egoogle.com:443"),
            (
                "normal 2",
                "client-api.arkoselabs.com:8080",
                b"\x44\x01\x1eclient-api.arkoselabs.com:8080",
            ),
            ("empty", "", b"\x44\x01\x00"),
        ];
        for (name, addr, want_prefix) in cases {
            let mut buf = Vec::new();
            write_tcp_request(&mut buf, addr)?;
            assert!(
                buf.starts_with(want_prefix) && buf.len() > want_prefix.len(),
                "write_tcp_request() prefix + padding: {name}",
            );
        }
        Ok(())
    }

    // Port of TestReadTCPResponse.
    #[test]
    fn read_tcp_response_cases() -> Result<()> {
        let cases: &[ReadResponseCase] = &[
            (
                "normal ok no padding",
                b"\x00\x0bhello world\x00",
                true,
                "hello world",
                false,
            ),
            (
                "normal error with padding",
                b"\x01\x06stop!!\x05xxxxx",
                false,
                "stop!!",
                false,
            ),
            (
                "normal ok no message with padding",
                b"\x01\x00\x05xxxxx",
                false,
                "",
                false,
            ),
            ("incomplete 1", b"\x00\x0bhoho", false, "", true),
            ("incomplete 2", b"\x01\x05jesus\x05x", false, "", true),
        ];
        for (name, data, want_ok, want_msg, want_err) in cases {
            let mut r = io::Cursor::new(*data);
            match read_tcp_response(&mut r) {
                Ok((ok, msg)) => {
                    assert!(
                        !want_err,
                        "read_tcp_response() unexpectedly succeeded: {name}"
                    );
                    assert_eq!(ok, *want_ok, "read_tcp_response() status: {name}");
                    assert_eq!(&msg, want_msg, "read_tcp_response() message: {name}");
                },
                Err(_) => assert!(want_err, "read_tcp_response() unexpectedly failed: {name}"),
            }
        }
        Ok(())
    }
}
