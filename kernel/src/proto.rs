//! Pure transport-and-resolver logic layered on the existing IPv4 stack: UDP,
//! DNS (A-record query build and response parse with name compression), TCP
//! segment build and parse, and HTTP/1.0 response parsing.
//!
//! Everything here is a pure function over byte slices with no hardware access,
//! no `asm!`, and no MMIO, so the exact code the kernel runs is unit-tested on
//! the host through the `aurora-logic` crate. The I/O side (virtio-net frames,
//! ARP, timing, the TCP driver loop) lives in `net.rs` and calls into this.

/// IPv4 protocol numbers.
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_TCP: u8 = 6;

// --- Internet checksum -------------------------------------------------------

/// Accumulate a 16-bit ones-complement sum over `data` into `acc`.
fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    acc
}

/// Fold and complement a running checksum accumulator into the final 16-bit word.
fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Standalone IPv4 header checksum over `hdr`.
pub fn ipv4_checksum(hdr: &[u8]) -> u16 {
    fold(sum16(hdr, 0))
}

/// Transport checksum (UDP or TCP) over the IPv4 pseudo-header plus `transport`.
/// The pseudo-header is src IP, dst IP, a zero byte, the protocol, and the
/// transport length. `transport` must already carry a zeroed checksum field.
pub fn transport_checksum(src: [u8; 4], dst: [u8; 4], proto: u8, transport: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src);
    pseudo[4..8].copy_from_slice(&dst);
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10..12].copy_from_slice(&(transport.len() as u16).to_be_bytes());
    let acc = sum16(&pseudo, 0);
    let mut c = fold(sum16(transport, acc));
    // A computed UDP checksum of zero is transmitted as all-ones (0xffff).
    if c == 0 && proto == IP_PROTO_UDP {
        c = 0xffff;
    }
    c
}

// --- UDP ---------------------------------------------------------------------

/// Build a UDP datagram (header + payload) into `out`, with the checksum filled
/// from the IPv4 pseudo-header. Returns the datagram length, or None if `out` is
/// too small.
pub fn build_udp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = 8 + payload.len();
    if out.len() < total {
        return None;
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum zero for now
    out[8..total].copy_from_slice(payload);
    let c = transport_checksum(src_ip, dst_ip, IP_PROTO_UDP, &out[..total]);
    out[6..8].copy_from_slice(&c.to_be_bytes());
    Some(total)
}

/// Parse a UDP datagram, returning `(src_port, dst_port, payload_offset,
/// payload_len)`. Does not verify the checksum (many stacks send zero).
pub fn parse_udp(dgram: &[u8]) -> Option<(u16, u16, usize, usize)> {
    if dgram.len() < 8 {
        return None;
    }
    let src = u16::from_be_bytes([dgram[0], dgram[1]]);
    let dst = u16::from_be_bytes([dgram[2], dgram[3]]);
    let len = u16::from_be_bytes([dgram[4], dgram[5]]) as usize;
    if len < 8 || len > dgram.len() {
        return None;
    }
    Some((src, dst, 8, len - 8))
}

// --- DNS ---------------------------------------------------------------------

/// Encode a hostname as DNS labels into `out` starting at `pos`, terminated by a
/// zero length byte. Returns the position after the terminator.
fn encode_name(name: &str, out: &mut [u8], mut pos: usize) -> Option<usize> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let l = label.len();
        if l > 63 || pos + 1 + l >= out.len() {
            return None;
        }
        out[pos] = l as u8;
        pos += 1;
        out[pos..pos + l].copy_from_slice(label.as_bytes());
        pos += l;
    }
    if pos >= out.len() {
        return None;
    }
    out[pos] = 0;
    pos += 1;
    Some(pos)
}

/// Build a DNS query for the A record of `name` with transaction id `id` and the
/// recursion-desired flag set. Returns the message length.
pub fn build_dns_query(id: u16, name: &str, out: &mut [u8]) -> Option<usize> {
    if out.len() < 12 {
        return None;
    }
    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD=1, standard query
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // ancount
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // nscount
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // arcount
    let mut pos = encode_name(name, out, 12)?;
    if pos + 4 > out.len() {
        return None;
    }
    out[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out[pos + 2..pos + 4].copy_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    pos += 4;
    Some(pos)
}

/// Advance past a DNS name at `pos`, honouring compression pointers. Returns the
/// position of the first byte after the name (for a pointer, two bytes on).
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos];
        if len & 0xc0 == 0xc0 {
            // Compression pointer: two bytes, and the name ends here.
            return if pos + 2 <= msg.len() { Some(pos + 2) } else { None };
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

/// Result of parsing a DNS response.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsResult {
    /// The first A record found.
    Ipv4([u8; 4]),
    /// A well-formed response with no A record (or a non-zero rcode).
    NoAddress,
    /// The id did not match, or the message was malformed.
    Invalid,
}

/// Parse a DNS response, returning the first A record whose class is IN. Handles
/// the header, the echoed question(s), and answer records using compression
/// pointers for the owner names.
pub fn parse_dns_response(msg: &[u8], want_id: u16) -> DnsResult {
    if msg.len() < 12 {
        return DnsResult::Invalid;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    if id != want_id {
        return DnsResult::Invalid;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return DnsResult::Invalid; // not a response
    }
    if flags & 0x000f != 0 {
        return DnsResult::NoAddress; // non-zero rcode
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    // Skip the question section.
    for _ in 0..qd {
        pos = match skip_name(msg, pos) {
            Some(p) => p,
            None => return DnsResult::Invalid,
        };
        pos += 4; // qtype + qclass
        if pos > msg.len() {
            return DnsResult::Invalid;
        }
    }
    // Walk the answer section.
    for _ in 0..an {
        pos = match skip_name(msg, pos) {
            Some(p) => p,
            None => return DnsResult::Invalid,
        };
        if pos + 10 > msg.len() {
            return DnsResult::Invalid;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return DnsResult::Invalid;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            return DnsResult::Ipv4([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]]);
        }
        pos += rdlen; // CNAME or other record, keep looking
    }
    DnsResult::NoAddress
}

// --- TCP ---------------------------------------------------------------------

/// TCP flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// A parsed TCP segment: sequence/ack numbers, flags, and the payload slice
/// offset and length within the segment.
#[derive(Debug, PartialEq, Eq)]
pub struct TcpSeg {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub data_off: usize,
    pub data_len: usize,
}

/// Build a TCP segment (header, no options, plus payload) into `out` with the
/// checksum filled from the IPv4 pseudo-header. Returns the segment length.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = 20 + payload.len();
    if out.len() < total {
        return None;
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&seq.to_be_bytes());
    out[8..12].copy_from_slice(&ack.to_be_bytes());
    out[12] = 5 << 4; // data offset 5 words (20 bytes), no options
    out[13] = flags;
    out[14..16].copy_from_slice(&window.to_be_bytes());
    out[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum zero for now
    out[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer
    out[20..total].copy_from_slice(payload);
    let c = transport_checksum(src_ip, dst_ip, IP_PROTO_TCP, &out[..total]);
    out[16..18].copy_from_slice(&c.to_be_bytes());
    Some(total)
}

/// Parse a TCP segment header, returning the fields and the payload location.
pub fn parse_tcp(seg: &[u8]) -> Option<TcpSeg> {
    if seg.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([seg[0], seg[1]]);
    let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
    let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
    let ack = u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]);
    let data_off = ((seg[12] >> 4) as usize) * 4;
    let flags = seg[13];
    let window = u16::from_be_bytes([seg[14], seg[15]]);
    if data_off < 20 || data_off > seg.len() {
        return None;
    }
    Some(TcpSeg {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        data_off,
        data_len: seg.len() - data_off,
    })
}

// --- Total per-operation receive budget --------------------------------------

/// A total, absolute receive budget for one whole fetch operation, metering both
/// wall-clock time and total wire bytes.
///
/// This is the universal fix for a receive-path slowloris. The per-record idle
/// counters elsewhere reset whenever a byte arrives, so a peer that dribbles one
/// byte at a time (never completing a record) keeps every idle counter pinned to
/// zero and pins the single core forever. This budget is different: the deadline
/// is ABSOLUTE for the operation. A byte arriving does NOT reset it. The byte cap
/// likewise counts every byte pulled off the wire, including bytes accumulating
/// inside a record that never completes, so even a fast flood that completes
/// nothing is bounded.
///
/// The wall-clock is supplied by the caller as a monotonic tick (the ARM generic
/// timer in the kernel, a synthetic value in host tests), keeping this type pure
/// and host-testable.
#[derive(Clone)]
pub struct RecvBudget {
    start: u64,
    deadline_ticks: u64,
    bytes: usize,
    max_bytes: usize,
    over_bytes: bool,
}

impl RecvBudget {
    /// Start a budget at tick `now`, expiring after `deadline_ticks` more ticks
    /// or after `max_bytes` total wire bytes, whichever comes first.
    pub fn new(now: u64, deadline_ticks: u64, max_bytes: usize) -> Self {
        Self {
            start: now,
            deadline_ticks,
            bytes: 0,
            max_bytes,
            over_bytes: false,
        }
    }

    /// True once the elapsed ticks since `start` exceed the deadline. Monotonic
    /// tick source, so `wrapping_sub` is only defensive against a counter wrap.
    pub fn time_exceeded(&self, now: u64) -> bool {
        now.wrapping_sub(self.start) > self.deadline_ticks
    }

    /// Charge `n` wire bytes. Returns `true` while within the byte cap and
    /// `false` the moment it is crossed; the over-budget state is sticky.
    pub fn charge(&mut self, n: usize) -> bool {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > self.max_bytes {
            self.over_bytes = true;
        }
        !self.over_bytes
    }

    /// True once the byte cap has been crossed.
    pub fn bytes_exceeded(&self) -> bool {
        self.over_bytes
    }

    /// The single check a receive loop makes each iteration: either the absolute
    /// deadline passed or the byte cap was crossed.
    pub fn over_budget(&self, now: u64) -> bool {
        self.over_bytes || self.time_exceeded(now)
    }

    #[allow(dead_code)] // used by host tests and available for diagnostics
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

// --- HTTP/1.0 ----------------------------------------------------------------

/// Parse an HTTP response: the status code from the status line and the offset
/// where the body begins (just past the blank line). Returns `(status, body_off)`.
pub fn parse_http_response(resp: &[u8]) -> Option<(u16, usize)> {
    // Status line: "HTTP/1.x SSS reason\r\n".
    if resp.len() < 12 || &resp[0..5] != b"HTTP/" {
        return None;
    }
    let sp = resp.iter().position(|&b| b == b' ')?;
    if sp + 4 > resp.len() {
        return None;
    }
    let code = &resp[sp + 1..sp + 4];
    if !code.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status = (code[0] - b'0') as u16 * 100
        + (code[1] - b'0') as u16 * 10
        + (code[2] - b'0') as u16;
    // Body starts after the first CRLFCRLF (or LFLF as a fallback).
    let body_off = find_body(resp)?;
    Some((status, body_off))
}

fn find_body(resp: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 3 < resp.len() {
        if &resp[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        i += 1;
    }
    let mut i = 0;
    while i + 1 < resp.len() {
        if &resp[i..i + 2] == b"\n\n" {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_budget_time_deadline_is_absolute() {
        // 1000-tick deadline, a huge byte cap so only time can trip it.
        let b = RecvBudget::new(100, 1000, usize::MAX);
        assert!(!b.over_budget(100)); // start
        assert!(!b.over_budget(1100)); // exactly at the deadline, still ok
        assert!(b.over_budget(1101)); // one tick past: expired
        assert!(b.time_exceeded(5000));
    }

    #[test]
    fn recv_budget_a_byte_does_not_reset_the_deadline() {
        // The slowloris property: charging bytes must never push the deadline
        // out. The deadline is measured only from `start`, regardless of traffic.
        let mut b = RecvBudget::new(0, 1000, usize::MAX);
        for now in [200u64, 400, 600, 800, 1000] {
            assert!(b.charge(1)); // a byte trickles in, well under the cap
            assert!(!b.over_budget(now));
        }
        // Time still runs out at the same absolute point despite the traffic.
        assert!(b.over_budget(1001));
    }

    #[test]
    fn recv_budget_byte_cap_trips_and_is_sticky() {
        // Small byte cap, effectively infinite time: only bytes can trip it.
        let mut b = RecvBudget::new(0, u64::MAX, 100);
        assert!(b.charge(60));
        assert!(!b.bytes_exceeded());
        assert!(!b.charge(50)); // 110 > 100: crosses the cap
        assert!(b.bytes_exceeded());
        assert!(b.over_budget(0)); // over even though time has not moved
        // The state is sticky and saturates rather than wrapping.
        assert!(!b.charge(usize::MAX));
        assert!(b.bytes_exceeded());
    }

    #[test]
    fn recv_budget_legit_fetch_stays_within_budget() {
        // A real fetch: a few hundred KB within a second, far under a multi-MB
        // cap and a multi-second deadline, never trips.
        let mut b = RecvBudget::new(0, 1_000_000_000, 4 * 1024 * 1024);
        for _ in 0..256 {
            assert!(b.charge(1400)); // ~358 KB total
        }
        assert!(!b.over_budget(500_000_000)); // half the deadline elapsed
        assert_eq!(b.bytes(), 256 * 1400);
    }
}
