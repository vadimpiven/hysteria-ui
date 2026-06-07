//! UDP message fragmentation and reassembly.
//!
//! Port of `core/internal/frag/frag.go`, kept structurally identical to the Go
//! source.

use super::protocol::UdpMessage;

/// Split `m` into fragments no larger than `max_size` bytes once serialized.
/// Returns a single-element vector when no fragmentation is needed, or an empty
/// vector when the header alone exceeds `max_size`.
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "fragment counts/ids are u8 by protocol"
)]
pub fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let full_payload = &m.data;
    let header_size = m.header_size();
    if max_size <= header_size {
        return Vec::new();
    }
    let max_payload_size = max_size - header_size;
    // REPORT UPSTREAM: a payload needing >255 fragments truncates `frag_count`
    // (`as u8`) and overflows `frag_id` in the loop below. The reference has the
    // same latent bug (`core/internal/frag/frag.go`: `uint8(...)` count, then
    // `frags[fragID]` would index out of bounds). Unreachable in practice — one
    // QUIC datagram payload is far below 255 × max_payload_size — and this is the
    // outbound/local-app path, not server-controlled input. Left faithful to Go.
    let frag_count = full_payload.len().div_ceil(max_payload_size) as u8; // round up
    let mut frags = Vec::with_capacity(frag_count as usize);
    let mut off = 0;
    let mut frag_id = 0u8;
    while off < full_payload.len() {
        let payload_size = (full_payload.len() - off).min(max_payload_size);
        let mut frag = m.clone();
        frag.frag_id = frag_id;
        frag.frag_count = frag_count;
        frag.data = full_payload[off..off + payload_size].to_vec();
        frags.push(frag);
        off += payload_size;
        frag_id += 1;
    }
    frags
}

/// Handles the defragmentation of UDP messages.
///
/// The current implementation can only handle one packet ID at a time. If
/// another packet arrives before a packet has received all fragments in their
/// entirety, any previous state is discarded.
#[derive(Default)]
pub struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: u8,
    size: usize, // data size
}

impl Defragger {
    /// Feed one (possibly fragmented) message; returns the reassembled message
    /// once all of its fragments have arrived, otherwise `None`.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            // wtf is this?
            return None;
        }
        let id = m.frag_id as usize;
        if m.packet_id != self.pkt_id || usize::from(m.frag_count) != self.frags.len() {
            // new message, clear previous state
            self.pkt_id = m.packet_id;
            self.frags = (0..m.frag_count).map(|_| None).collect();
            self.count = 1;
            self.size = m.data.len();
            self.frags[id] = Some(m);
        } else if self.frags[id].is_none() {
            self.count += 1;
            self.size += m.data.len();
            self.frags[id] = Some(m);
            if usize::from(self.count) == self.frags.len() {
                // all fragments received, assemble
                let mut data = Vec::with_capacity(self.size);
                for frag in self.frags.iter().flatten() {
                    data.extend_from_slice(&frag.data);
                }
                if let Some(mut assembled) = self.frags[id].take() {
                    assembled.data = data;
                    assembled.frag_id = 0;
                    assembled.frag_count = 1;
                    return Some(assembled);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    // Named case shapes for the table-driven tests (otherwise too complex for
    // clippy's `type_complexity` threshold).
    type FragExpect = (u8, u8, &'static [u8]);
    type FragCase = (&'static str, &'static [u8], usize, &'static [FragExpect]);
    type DefragCase = (&'static str, UdpMessage, Option<UdpMessage>);

    fn msg(packet_id: u16, frag_id: u8, frag_count: u8, data: &[u8]) -> UdpMessage {
        UdpMessage {
            session_id: 123,
            packet_id,
            frag_id,
            frag_count,
            addr: "test:123".into(),
            data: data.to_vec(),
        }
    }

    // Port of TestFragUDPMessage.
    #[test]
    fn frag_udp_message_cases() {
        // (name, packet data, max_size, expected (frag_id, frag_count, data))
        let cases: &[FragCase] = &[
            ("no frag", b"hello", 100, &[(0, 1, b"hello")]),
            ("2 frags", b"hello", 20, &[(0, 2, b"hel"), (1, 2, b"lo")]),
            (
                "4 frags",
                b"abcdefgh",
                19,
                &[(0, 4, b"ab"), (1, 4, b"cd"), (2, 4, b"ef"), (3, 4, b"gh")],
            ),
        ];
        for (name, data, max_size, want) in cases {
            let source = msg(123, 0, 1, data);
            let got = frag_udp_message(&source, *max_size);
            let want_msgs: Vec<UdpMessage> = want
                .iter()
                .map(|(fid, fc, d)| msg(123, *fid, *fc, d))
                .collect();
            assert_eq!(got, want_msgs, "frag_udp_message(): {name}");
        }
    }

    // Port of TestDefragger. A single Defragger is fed the whole sequence, as in
    // the Go test, so cross-message state carries between cases.
    #[test]
    fn defragger_sequence() {
        // (name, input, expected output)
        let cases: Vec<DefragCase> = vec![
            (
                "no frag",
                msg(987, 0, 1, b"hello"),
                Some(msg(987, 0, 1, b"hello")),
            ),
            ("frag 0 - 1/2", msg(987, 0, 2, b"hello "), None),
            (
                "frag 0 - 2/2",
                msg(987, 1, 2, b"moto"),
                Some(msg(987, 0, 1, b"hello moto")),
            ),
            ("frag 1 - 1/3", msg(987, 0, 3, b"deco"), None),
            ("frag 1 - 2/3", msg(987, 1, 3, b"*"), None),
            (
                "frag 1 - 3/3",
                msg(987, 2, 3, b"27"),
                Some(msg(987, 0, 1, b"deco*27")),
            ),
            ("frag 2 - 1/2", msg(233, 1, 2, b"shinsekai"), None),
            ("frag 3 - 2/2", msg(244, 1, 2, b"what???"), None),
            ("frag 2 - 2/2", msg(233, 1, 2, b" annaijo"), None),
            ("invalid id", msg(233, 88, 2, b"shinsekai"), None),
            (
                "frag 2 - 1/2 re",
                msg(233, 0, 2, b"shinsekai"),
                Some(msg(233, 0, 1, b"shinsekai annaijo")),
            ),
        ];

        let mut d = Defragger::default();
        for (name, input, want) in cases {
            assert_eq!(d.feed(input), want, "Defragger::feed(): {name}");
        }
    }
}
