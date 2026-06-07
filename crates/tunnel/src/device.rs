//! A smoltcp [`Device`] backed by in-memory packet queues.
//!
//! smoltcp's poll loop is synchronous; the TUN I/O is async. This device is the
//! seam: the netstack task drains the TUN into `inbound` and writes `outbound`
//! back out. `inbound` is peeked before each poll to detect new flows.

use std::collections::VecDeque;

use smoltcp::phy::Device;
use smoltcp::phy::DeviceCapabilities;
use smoltcp::phy::Medium;
use smoltcp::phy::RxToken;
use smoltcp::phy::TxToken;
use smoltcp::time::Instant;

pub(crate) struct TunDevice {
    mtu: usize,
    /// IP packets read from the TUN, awaiting injection into the netstack.
    inbound: VecDeque<Vec<u8>>,
    /// IP packets the netstack produced, awaiting a write to the TUN.
    outbound: VecDeque<Vec<u8>>,
}

impl TunDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            mtu,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    pub(crate) fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    /// Discard the next inbound packet. Used to decline a flow without letting
    /// the poll see it: an un-accepted SYN/datagram would otherwise be answered
    /// with a RST (or ICMP reject) because `any_ip` treats every destination as
    /// local. Dropping it instead makes the client retransmit, like a real
    /// listener whose backlog is full.
    pub(crate) fn pop_inbound(&mut self) {
        self.inbound.pop_front();
    }

    pub(crate) fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    /// The next inbound packet without consuming it (used for flow detection).
    pub(crate) fn peek_inbound(&self) -> Option<&[u8]> {
        self.inbound.front().map(Vec::as_slice)
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((TunRxToken(packet), TunTxToken(&mut self.outbound)))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // A TUN carries raw IP packets (no link-layer header).
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub(crate) struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub(crate) struct TunTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for TunTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}
