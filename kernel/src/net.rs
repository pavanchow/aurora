//! A from-scratch virtio-net driver and a minimal network stack: Ethernet, ARP,
//! IPv4, ICMP, and now the transport and resolver layers an agent needs to pull
//! real bytes off the internet into the amnesic session: UDP, a DNS resolver, a
//! one-shot TCP client, and an HTTP/1.0 client behind the `fetch` command.
//!
//! The device is a modern (version 2) virtio-mmio virtio-net NIC on the QEMU
//! `virt` machine, attached with `-netdev user,... -device virtio-net-device`.
//! The driver brings the device up (reset, feature negotiation for VERSION_1 and
//! MAC, split virtqueues), then the stack does real request/response round trips
//! over QEMU's user-mode network.
//!
//! All of it is gated by CAP_NET, which is off by default and revocable, so the
//! trace-free posture holds unless a session explicitly asks for the network.
//!
//! Amnesia: every network buffer, including the virtio DMA rings, the per-frame
//! receive scratch, and the fetched HTTP body, lives in the reserved `netbuf`
//! region (see `mem::netbuf_region_range`). A `wipe` scrubs that whole region, so
//! fetched bytes never survive a teardown. Pure header build/parse/checksum and
//! the DNS/HTTP wire logic live in `proto.rs` and are unit-tested on the host.
//!
//! Zero external crates. Polling only (no NIC IRQ). Cache maintenance is elided
//! because QEMU TCG has no cache between the CPU and the emulated DMA; barriers
//! order the ring updates. Limits: one TCP connection at a time, HTTP/1.0 only
//! (no TLS/HTTPS), and no congestion control.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{compiler_fence, Ordering};

use crate::proto::{self, DnsResult};
use crate::tls::{self, TrafficKeys};
use crate::{ed25519, entropy, mem, print, println, x25519, x509};

// virtio-mmio on QEMU virt: 32 slots, 0x200 bytes apart, from 0x0a00_0000.
const MMIO_BASE: usize = 0x0a00_0000;
const MMIO_STRIDE: usize = 0x200;
const MMIO_SLOTS: usize = 32;

// Register offsets.
const R_MAGIC: usize = 0x000;
const R_VERSION: usize = 0x004;
const R_DEVICE_ID: usize = 0x008;
const R_DEVICE_FEATURES: usize = 0x010;
const R_DEVICE_FEATURES_SEL: usize = 0x014;
const R_DRIVER_FEATURES: usize = 0x020;
const R_DRIVER_FEATURES_SEL: usize = 0x024;
const R_QUEUE_SEL: usize = 0x030;
const R_QUEUE_NUM_MAX: usize = 0x034;
const R_QUEUE_NUM: usize = 0x038;
const R_QUEUE_READY: usize = 0x044;
const R_QUEUE_NOTIFY: usize = 0x050;
const R_STATUS: usize = 0x070;
const R_QUEUE_DESC_LOW: usize = 0x080;
const R_QUEUE_DESC_HIGH: usize = 0x084;
const R_QUEUE_DRIVER_LOW: usize = 0x090;
const R_QUEUE_DRIVER_HIGH: usize = 0x094;
const R_QUEUE_DEVICE_LOW: usize = 0x0a0;
const R_QUEUE_DEVICE_HIGH: usize = 0x0a4;
const R_CONFIG: usize = 0x100;

const MAGIC: u32 = 0x7472_6976; // "virt"
const DEV_NET: u32 = 1;

// Status bits.
const S_ACK: u32 = 1;
const S_DRIVER: u32 = 2;
const S_DRIVER_OK: u32 = 4;
const S_FEATURES_OK: u32 = 8;

// Feature bits.
const F_NET_MAC: u32 = 5; // low word
const F_VERSION_1: u32 = 32; // high word bit 0

// Virtqueue descriptor flag: device-writable (used for receive buffers).
const VRING_DESC_F_WRITE: u16 = 2;

const QSIZE: usize = 8;
const BUF_SIZE: usize = 2048;
const NET_HDR_LEN: usize = 12; // modern virtio_net_hdr

const RX_SCRATCH: usize = 2048; // one received frame at a time
const BODY_MAX: usize = 32768; // fetched HTTP response cap (headers + body)

#[repr(C)]
#[derive(Clone, Copy)]
struct VqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QSIZE],
    used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VqUsed {
    flags: u16,
    idx: u16,
    ring: [VqUsedElem; QSIZE],
    avail_event: u16,
}

#[repr(C, align(4096))]
struct Queue {
    desc: [VqDesc; QSIZE],
    avail: VqAvail,
    used: VqUsed,
}

#[repr(C, align(4096))]
struct Buf([u8; BUF_SIZE]);

// TLS working-memory sizes. A TLS 1.3 record ciphertext is at most 2^14+256
// bytes; the stream reassembly and handshake-flight buffers must hold at least
// one such record plus a server's full handshake flight (cert chain included).
const TLS_STREAM_MAX: usize = 34816;
const TLS_HS_MAX: usize = 16384;
const TLS_REC_MAX: usize = 17408;
const TLS_SUBJECT_MAX: usize = 128;

/// The certificate-validation level Aurora actually reached on a connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CertLevel {
    /// The CertificateVerify signature was verified against the leaf public key
    /// (the handshake transcript is cryptographically bound to that key) AND the
    /// SNI host matched the certificate. This is authenticated-to-leaf.
    AuthenticatedToLeaf,
    /// The encrypted channel was established and the leaf certificate parsed, but
    /// its signature scheme is one Aurora does not yet verify (e.g. ECDSA/RSA), so
    /// the leaf binding was not proven. Documented, never overclaimed.
    EncryptedUnverified,
    /// An explicit insecure mode used for the deterministic local self-test.
    InsecurePinned,
}

/// All TLS session working memory, resident in the wiped `netbuf` region so a
/// wipe scrubs the x25519 private key, every traffic key, and the transcript.
/// The decrypted application plaintext lands in `NetScratch::body`, also wiped.
#[repr(C, align(4096))]
struct TlsSession {
    priv_key: [u8; 32],
    client_random: [u8; 32],
    session_id: [u8; 32],
    server_pub: [u8; 32],
    ks: tls::KeySchedule,
    c_hs_secret: [u8; 32],
    s_hs_secret: [u8; 32],
    c_hs: TrafficKeys,
    s_hs: TrafficKeys,
    c_ap: TrafficKeys,
    s_ap: TrafficKeys,
    transcript: tls::Transcript,
    // Leaf-certificate facts captured while processing the handshake, used to
    // verify CertificateVerify and to report the validation level.
    leaf_pub: [u8; 32],
    leaf_alg: u8, // 0 ed25519, 1 ec-p256, 2 rsa, 3 other
    th_cert: [u8; 32], // transcript hash through the Certificate message
    name_ok: bool,
    leaf_verified: bool,
    cipher_suite: u16,
    group: u16,
    sig_scheme: u16,
    level: CertLevel,
    subject: [u8; TLS_SUBJECT_MAX],
    subject_len: usize,
}

#[repr(C, align(4096))]
struct TlsScratch {
    session: TlsSession,
    stream: [u8; TLS_STREAM_MAX],
    hs_buf: [u8; TLS_HS_MAX],
    rec: [u8; TLS_REC_MAX],
}

/// All network buffers, laid out in the reserved `netbuf` region so a wipe scrubs
/// them whole. Never a `static`: it is accessed through the fixed region address
/// so no fetched byte ever lands in memory the wipe does not cover.
#[repr(C, align(4096))]
struct NetScratch {
    rxq: Queue,
    txq: Queue,
    rx_bufs: [Buf; QSIZE],
    tx_buf: Buf,
    rx_scratch: [u8; RX_SCRATCH],
    body: [u8; BODY_MAX],
    tls: TlsScratch,
}

/// Raw pointer to the network scratch at the base of the reserved region.
#[inline]
fn nb() -> *mut NetScratch {
    mem::netbuf_region_range().0 as *mut NetScratch
}

struct NetState {
    base: usize,
    mac: [u8; 6],
    up: bool,
    rx_used_seen: u16,
    tx_used_seen: u16,
    tx_avail: u16,
}

static mut NET: NetState = NetState {
    base: 0,
    mac: [0; 6],
    up: false,
    rx_used_seen: 0,
    tx_used_seen: 0,
    tx_avail: 0,
};

// Static network identity on QEMU user-net (SLIRP).
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];
// QEMU user-net built-in DNS. Overridable by `resolve <name> <ns-ip>`.
const DEFAULT_NS: [u8; 4] = [10, 0, 2, 3];

#[inline]
fn mb() {
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
    compiler_fence(Ordering::SeqCst);
}

#[inline]
fn rd(base: usize, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

#[inline]
fn wr(base: usize, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) };
}

/// Scan the virtio-mmio slots for a virtio-net device.
fn find_device() -> Option<usize> {
    for slot in 0..MMIO_SLOTS {
        let base = MMIO_BASE + slot * MMIO_STRIDE;
        if rd(base, R_MAGIC) == MAGIC && rd(base, R_DEVICE_ID) == DEV_NET {
            return Some(base);
        }
    }
    None
}

fn setup_queue(base: usize, sel: u32, q: *mut Queue) -> bool {
    wr(base, R_QUEUE_SEL, sel);
    if rd(base, R_QUEUE_READY) != 0 {
        return false;
    }
    let max = rd(base, R_QUEUE_NUM_MAX);
    if max == 0 || (max as usize) < QSIZE {
        return false;
    }
    wr(base, R_QUEUE_NUM, QSIZE as u32);
    let desc = unsafe { addr_of!((*q).desc) } as u64;
    let avail = unsafe { addr_of!((*q).avail) } as u64;
    let used = unsafe { addr_of!((*q).used) } as u64;
    wr(base, R_QUEUE_DESC_LOW, desc as u32);
    wr(base, R_QUEUE_DESC_HIGH, (desc >> 32) as u32);
    wr(base, R_QUEUE_DRIVER_LOW, avail as u32);
    wr(base, R_QUEUE_DRIVER_HIGH, (avail >> 32) as u32);
    wr(base, R_QUEUE_DEVICE_LOW, used as u32);
    wr(base, R_QUEUE_DEVICE_HIGH, (used >> 32) as u32);
    mb();
    wr(base, R_QUEUE_READY, 1);
    true
}

/// Add an RX buffer index to the receive queue's available ring.
fn rx_post(base: usize, i: usize) {
    unsafe {
        let q = addr_of_mut!((*nb()).rxq);
        let buf = addr_of!((*nb()).rx_bufs[i]) as u64;
        (*q).desc[i] = VqDesc {
            addr: buf,
            len: BUF_SIZE as u32,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };
        let idx = core::ptr::read_volatile(addr_of!((*q).avail.idx));
        let slot = (idx as usize) % QSIZE;
        core::ptr::write_volatile(addr_of_mut!((*q).avail.ring[slot]), i as u16);
        mb();
        core::ptr::write_volatile(addr_of_mut!((*q).avail.idx), idx.wrapping_add(1));
        mb();
    }
    wr(base, R_QUEUE_NOTIFY, 0);
}

/// Bring the NIC up: reset, negotiate features, set up the two virtqueues, and
/// post all receive buffers. Returns false if no device or negotiation failed.
pub fn init() -> bool {
    if unsafe { *addr_of!(NET.up) } {
        return true;
    }
    // The scratch struct must fit in the reserved region.
    let (rs, re) = mem::netbuf_region_range();
    if core::mem::size_of::<NetScratch>() > re - rs {
        println!("[net] netbuf region too small for scratch, aborting");
        return false;
    }
    let base = match find_device() {
        Some(b) => b,
        None => {
            println!("[net] no virtio-net device found");
            return false;
        }
    };
    let version = rd(base, R_VERSION);
    println!("[net] virtio-net at {:#x} (mmio version {})", base, version);

    // Reset and start the handshake.
    wr(base, R_STATUS, 0);
    mb();
    wr(base, R_STATUS, S_ACK);
    wr(base, R_STATUS, S_ACK | S_DRIVER);

    // Read device features (low and high 32 bits).
    wr(base, R_DEVICE_FEATURES_SEL, 0);
    let dev_lo = rd(base, R_DEVICE_FEATURES);
    wr(base, R_DEVICE_FEATURES_SEL, 1);
    let dev_hi = rd(base, R_DEVICE_FEATURES);

    let want_mac = dev_lo & (1 << F_NET_MAC) != 0;
    let have_v1 = dev_hi & (1 << (F_VERSION_1 - 32)) != 0;
    if !have_v1 {
        println!("[net] device does not offer VIRTIO_F_VERSION_1, aborting");
        wr(base, R_STATUS, 0x80); // FAILED
        return false;
    }
    // Negotiate exactly VERSION_1 (+ MAC if offered): no offloads we cannot do.
    let drv_lo = if want_mac { 1 << F_NET_MAC } else { 0 };
    let drv_hi = 1 << (F_VERSION_1 - 32);
    wr(base, R_DRIVER_FEATURES_SEL, 0);
    wr(base, R_DRIVER_FEATURES, drv_lo);
    wr(base, R_DRIVER_FEATURES_SEL, 1);
    wr(base, R_DRIVER_FEATURES, drv_hi);
    println!(
        "[net] features: device={:#010x}_{:08x}, negotiated VERSION_1{}",
        dev_hi,
        dev_lo,
        if want_mac { "+MAC" } else { "" }
    );

    wr(base, R_STATUS, S_ACK | S_DRIVER | S_FEATURES_OK);
    mb();
    if rd(base, R_STATUS) & S_FEATURES_OK == 0 {
        println!("[net] FEATURES_OK rejected by device");
        wr(base, R_STATUS, 0x80);
        return false;
    }

    let (rxq_ptr, txq_ptr) = unsafe { (addr_of_mut!((*nb()).rxq), addr_of_mut!((*nb()).txq)) };
    if !setup_queue(base, 0, rxq_ptr) || !setup_queue(base, 1, txq_ptr) {
        println!("[net] virtqueue setup failed");
        return false;
    }

    // Read the MAC from config space if negotiated.
    let mut mac = [0u8; 6];
    if want_mac {
        for (i, m) in mac.iter_mut().enumerate() {
            *m = unsafe { core::ptr::read_volatile((base + R_CONFIG + i) as *const u8) };
        }
    }

    wr(base, R_STATUS, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
    mb();

    unsafe {
        NET.base = base;
        NET.mac = mac;
        NET.up = true;
        NET.rx_used_seen = 0;
        NET.tx_used_seen = 0;
        NET.tx_avail = 0;
    }

    // Post all receive buffers.
    for i in 0..QSIZE {
        rx_post(base, i);
    }

    println!(
        "[net] up: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, IP {}.{}.{}.{}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], OUR_IP[0], OUR_IP[1], OUR_IP[2], OUR_IP[3]
    );
    true
}

/// Reset the driver's "up" flag. Called by `wipe`, which zeroes the netbuf region
/// (including the DMA rings), so the next network use re-initializes the device
/// from scratch instead of trusting stale, now-zeroed rings.
pub fn on_wipe() {
    unsafe {
        NET.up = false;
        NET.base = 0;
    }
}

/// Transmit one Ethernet frame (already including dst/src MAC + ethertype).
fn send_frame(frame: &[u8]) {
    let base = unsafe { NET.base };
    unsafe {
        let tx = addr_of_mut!((*nb()).txq);
        let buf = addr_of_mut!((*nb()).tx_buf.0) as *mut u8;
        // 12-byte virtio-net header of zeros, then the frame.
        for i in 0..NET_HDR_LEN {
            core::ptr::write_volatile(buf.add(i), 0);
        }
        for (i, &b) in frame.iter().enumerate() {
            core::ptr::write_volatile(buf.add(NET_HDR_LEN + i), b);
        }
        (*tx).desc[0] = VqDesc {
            addr: buf as u64,
            len: (NET_HDR_LEN + frame.len()) as u32,
            flags: 0,
            next: 0,
        };
        let idx = core::ptr::read_volatile(addr_of!((*tx).avail.idx));
        let slot = (idx as usize) % QSIZE;
        core::ptr::write_volatile(addr_of_mut!((*tx).avail.ring[slot]), 0u16);
        mb();
        core::ptr::write_volatile(addr_of_mut!((*tx).avail.idx), idx.wrapping_add(1));
        mb();
    }
    wr(base, R_QUEUE_NOTIFY, 1);
}

/// Poll for one received frame into `out`, returning the frame length (excluding
/// the virtio-net header) or None after a bounded spin.
fn recv_frame(out: &mut [u8]) -> Option<usize> {
    let base = unsafe { NET.base };
    for _ in 0..20_000_000u64 {
        unsafe {
            let rx = addr_of_mut!((*nb()).rxq);
            let used_idx = core::ptr::read_volatile(addr_of!((*rx).used.idx));
            let seen = NET.rx_used_seen;
            if used_idx != seen {
                let slot = (seen as usize) % QSIZE;
                let elem = core::ptr::read_volatile(addr_of!((*rx).used.ring[slot]));
                let id = elem.id as usize % QSIZE;
                let total = elem.len as usize;
                let frame_len = total.saturating_sub(NET_HDR_LEN);
                let src = addr_of!((*nb()).rx_bufs[id].0) as *const u8;
                let n = core::cmp::min(frame_len, out.len());
                for (i, o) in out.iter_mut().take(n).enumerate() {
                    *o = core::ptr::read_volatile(src.add(NET_HDR_LEN + i));
                }
                NET.rx_used_seen = seen.wrapping_add(1);
                // Re-post this buffer.
                rx_post(base, id);
                return Some(n);
            }
        }
        core::hint::spin_loop();
    }
    None
}

// --- Ethernet / ARP / IPv4 / ICMP -------------------------------------------

const ET_ARP: u16 = 0x0806;
const ET_IPV4: u16 = 0x0800;
const BROADCAST: [u8; 6] = [0xff; 6];

fn our_mac() -> [u8; 6] {
    unsafe { NET.mac }
}

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

fn in_our_subnet(ip: [u8; 4]) -> bool {
    ip[0] == OUR_IP[0] && ip[1] == OUR_IP[1] && ip[2] == OUR_IP[2]
}

/// Send an ARP request for `ip` and wait for the reply, returning its MAC. A
/// genuine TX+RX round trip through the virtual network.
fn arp_resolve(ip: [u8; 4]) -> Option<[u8; 6]> {
    let mac = our_mac();
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&BROADCAST);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ET_ARP.to_be_bytes());
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // htype ethernet
    f[16..18].copy_from_slice(&ET_IPV4.to_be_bytes()); // ptype IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&1u16.to_be_bytes()); // op request
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&OUR_IP);
    f[32..38].copy_from_slice(&[0u8; 6]);
    f[38..42].copy_from_slice(&ip);
    send_frame(&f);

    let mut buf = [0u8; BUF_SIZE];
    for _ in 0..8 {
        let n = recv_frame(&mut buf)?;
        if n >= 42 {
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            let op = u16::from_be_bytes([buf[20], buf[21]]);
            if et == ET_ARP && op == 2 && buf[28..32] == ip {
                let mut m = [0u8; 6];
                m.copy_from_slice(&buf[22..28]);
                return Some(m);
            }
        }
    }
    None
}

/// Resolve the layer-2 next hop for `dst_ip`: the host itself if it is on our
/// subnet, otherwise the gateway.
fn next_hop_mac(dst_ip: [u8; 4]) -> Option<[u8; 6]> {
    let target = if in_our_subnet(dst_ip) { dst_ip } else { GW_IP };
    arp_resolve(target)
}

fn ip_checksum(data: &[u8]) -> u16 {
    proto::ipv4_checksum(data)
}

/// Send one IPv4 packet carrying `payload` (a UDP or TCP segment) to `dst_ip` via
/// `dst_mac`. The don't-fragment flag is set so responses come back as transport
/// segments, never IP fragments.
fn send_ipv4(dst_mac: [u8; 6], dst_ip: [u8; 4], protocol: u8, payload: &[u8]) -> bool {
    let mac = our_mac();
    let ip_total = 20 + payload.len();
    let frame_len = 14 + ip_total;
    let mut f = [0u8; 14 + 20 + 1500];
    if frame_len > f.len() {
        return false;
    }
    f[0..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ET_IPV4.to_be_bytes());
    f[14] = 0x45; // version 4, IHL 5
    f[15] = 0;
    f[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    f[18..20].copy_from_slice(&0u16.to_be_bytes()); // id
    f[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    f[22] = 64; // TTL
    f[23] = protocol;
    f[26..30].copy_from_slice(&OUR_IP);
    f[30..34].copy_from_slice(&dst_ip);
    let c = ip_checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    f[34..34 + payload.len()].copy_from_slice(payload);
    send_frame(&f[..frame_len]);
    true
}

/// Send an ICMP echo request carrying `token` to the gateway and wait for the
/// echo reply, returning the echoed token bytes.
fn icmp_echo(gw: [u8; 6], token: &[u8]) -> Option<[u8; 16]> {
    let mac = our_mac();
    let payload_len = core::cmp::min(token.len(), 16);
    let icmp_len = 8 + payload_len;
    let ip_total = 20 + icmp_len;
    let frame_len = 14 + ip_total;

    let mut f = [0u8; 14 + 20 + 8 + 16];
    f[0..6].copy_from_slice(&gw);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ET_IPV4.to_be_bytes());
    f[14] = 0x45;
    f[15] = 0;
    f[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    f[18..20].copy_from_slice(&0x1234u16.to_be_bytes());
    f[20..22].copy_from_slice(&0u16.to_be_bytes());
    f[22] = 64;
    f[23] = 1; // ICMP
    f[26..30].copy_from_slice(&OUR_IP);
    f[30..34].copy_from_slice(&GW_IP);
    let ipcsum = ip_checksum(&f[14..34]);
    f[24..26].copy_from_slice(&ipcsum.to_be_bytes());
    let icmp = 34;
    f[icmp] = 8; // echo request
    f[icmp + 1] = 0;
    f[icmp + 4..icmp + 6].copy_from_slice(&0xABCDu16.to_be_bytes());
    f[icmp + 6..icmp + 8].copy_from_slice(&1u16.to_be_bytes());
    f[icmp + 8..icmp + 8 + payload_len].copy_from_slice(&token[..payload_len]);
    let icmpcsum = ip_checksum(&f[icmp..icmp + icmp_len]);
    f[icmp + 2..icmp + 4].copy_from_slice(&icmpcsum.to_be_bytes());

    send_frame(&f[..frame_len]);

    let mut buf = [0u8; BUF_SIZE];
    for _ in 0..8 {
        let n = recv_frame(&mut buf)?;
        if n >= frame_len {
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            if et == ET_IPV4 && buf[23] == 1 {
                let ihl = ((buf[14] & 0x0f) as usize) * 4;
                let icmp = 14 + ihl;
                if buf[icmp] == 0 && buf.len() >= icmp + 8 + payload_len {
                    let mut echoed = [0u8; 16];
                    echoed[..payload_len].copy_from_slice(&buf[icmp + 8..icmp + 8 + payload_len]);
                    return Some(echoed);
                }
            }
        }
    }
    None
}

// --- UDP / DNS ---------------------------------------------------------------

/// A weakly-random 16-bit value from the cycle counter, for DNS ids and ports.
fn rand16() -> u16 {
    let c = cntpct();
    ((c ^ (c >> 17) ^ (c >> 31)) as u16) | 1
}

/// Resolve `name`'s A record via the DNS server `ns_ip` over UDP. Returns the
/// IPv4 address, or None on timeout or no address. The response lands in the
/// wiped netbuf region.
pub fn resolve(name: &str, ns_ip: [u8; 4]) -> Option<[u8; 4]> {
    if !init() {
        return None;
    }
    let ns_mac = next_hop_mac(ns_ip)?;
    let id = rand16();
    let src_port = 0xC000 | (rand16() & 0x0fff);

    let mut query = [0u8; 512];
    let qlen = proto::build_dns_query(id, name, &mut query)?;
    let mut udp = [0u8; 600];
    let ulen = proto::build_udp(OUR_IP, ns_ip, src_port, 53, &query[..qlen], &mut udp)?;

    for _ in 0..4 {
        send_ipv4(ns_mac, ns_ip, proto::IP_PROTO_UDP, &udp[..ulen]);
        // Wait for a matching UDP response from the nameserver.
        for _ in 0..16 {
            let rx: &mut [u8] = unsafe { &mut (*nb()).rx_scratch };
            let n = match recv_frame(rx) {
                Some(n) => n,
                None => break, // timeout: retransmit the query
            };
            if n < 34 || u16::from_be_bytes([rx[12], rx[13]]) != ET_IPV4 {
                continue;
            }
            if rx[23] != proto::IP_PROTO_UDP || rx[26..30] != ns_ip {
                continue;
            }
            let ihl = ((rx[14] & 0x0f) as usize) * 4;
            let ip_total = u16::from_be_bytes([rx[16], rx[17]]) as usize;
            let off = 14 + ihl;
            let end = 14 + ip_total;
            if end > n || off + 8 > end {
                continue;
            }
            let (sp, _dp, poff, plen) = match proto::parse_udp(&rx[off..end]) {
                Some(x) => x,
                None => continue,
            };
            if sp != 53 {
                continue;
            }
            let ds = off + poff;
            match proto::parse_dns_response(&rx[ds..ds + plen], id) {
                DnsResult::Ipv4(ip) => return Some(ip),
                DnsResult::NoAddress => return None,
                DnsResult::Invalid => continue,
            }
        }
    }
    None
}

// --- TCP one-shot client -----------------------------------------------------

/// State for one active outbound TCP connection.
struct Tcp {
    dst_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_port: u16,
    src_port: u16,
    snd_nxt: u32,
    rcv_nxt: u32,
}

const TCP_WINDOW: u16 = 32768;
const MAX_FRAMES_PER_POLL: usize = 24;

fn tcp_send(t: &Tcp, flags: u8, payload: &[u8]) -> bool {
    let mut seg = [0u8; 20 + 1460];
    let len = match proto::build_tcp(
        OUR_IP, t.dst_ip, t.src_port, t.dst_port, t.snd_nxt, t.rcv_nxt, flags, TCP_WINDOW, payload,
        &mut seg,
    ) {
        Some(l) => l,
        None => return false,
    };
    send_ipv4(t.dst_mac, t.dst_ip, proto::IP_PROTO_TCP, &seg[..len])
}

/// Poll for the next TCP segment of this connection. Copies its payload into
/// `out` and returns `(seq, ack, flags, payload_len)`, or None on timeout.
fn tcp_poll(t: &Tcp, out: &mut [u8]) -> Option<(u32, u32, u8, usize)> {
    for _ in 0..MAX_FRAMES_PER_POLL {
        let rx: &mut [u8] = unsafe { &mut (*nb()).rx_scratch };
        let n = recv_frame(rx)?;
        if n < 34 || u16::from_be_bytes([rx[12], rx[13]]) != ET_IPV4 {
            continue;
        }
        if rx[23] != proto::IP_PROTO_TCP || rx[26..30] != t.dst_ip {
            continue;
        }
        let ihl = ((rx[14] & 0x0f) as usize) * 4;
        let ip_total = u16::from_be_bytes([rx[16], rx[17]]) as usize;
        let seg_off = 14 + ihl;
        let seg_end = 14 + ip_total;
        if seg_end > n || seg_off + 20 > seg_end {
            continue;
        }
        let seg = match proto::parse_tcp(&rx[seg_off..seg_end]) {
            Some(s) => s,
            None => continue,
        };
        if seg.src_port != t.dst_port || seg.dst_port != t.src_port {
            continue;
        }
        let dlen = core::cmp::min(seg.data_len, out.len());
        let dstart = seg_off + seg.data_off;
        out[..dlen].copy_from_slice(&rx[dstart..dstart + dlen]);
        return Some((seg.seq, seg.ack, seg.flags, dlen));
    }
    None
}

/// Open a TCP connection with the three-way handshake. Retransmits the SYN a
/// bounded number of times so a lost packet cannot hang the client.
fn tcp_connect(dst_ip: [u8; 4], dst_mac: [u8; 6], dst_port: u16) -> Option<Tcp> {
    let iss = ((cntpct() as u32).wrapping_mul(2_654_435_761)) ^ 0x5f37_59df;
    let src_port = 0xC000 | (rand16() & 0x0fff);
    let mut t = Tcp {
        dst_ip,
        dst_mac,
        dst_port,
        src_port,
        snd_nxt: iss,
        rcv_nxt: 0,
    };
    let mut scratch = [0u8; 64];
    for _ in 0..6 {
        // SYN carries one sequence number.
        t.snd_nxt = iss;
        tcp_send(&t, proto::TCP_SYN, &[]);
        if let Some((seq, ack, flags, _)) = tcp_poll(&t, &mut scratch) {
            if flags & proto::TCP_RST != 0 {
                return None;
            }
            if flags & (proto::TCP_SYN | proto::TCP_ACK) == (proto::TCP_SYN | proto::TCP_ACK)
                && ack == iss.wrapping_add(1)
            {
                t.rcv_nxt = seq.wrapping_add(1);
                t.snd_nxt = iss.wrapping_add(1);
                tcp_send(&t, proto::TCP_ACK, &[]);
                return Some(t);
            }
        }
    }
    None
}

/// Send the FIN teardown and briefly acknowledge the peer's FIN.
fn tcp_close(t: &mut Tcp) {
    tcp_send(t, proto::TCP_FIN | proto::TCP_ACK, &[]);
    t.snd_nxt = t.snd_nxt.wrapping_add(1);
    let mut scratch = [0u8; 64];
    for _ in 0..4 {
        match tcp_poll(t, &mut scratch) {
            Some((seq, _ack, flags, dlen)) => {
                if flags & proto::TCP_FIN != 0 {
                    t.rcv_nxt = seq.wrapping_add(dlen as u32).wrapping_add(1);
                    tcp_send(t, proto::TCP_ACK, &[]);
                    break;
                }
            }
            None => break,
        }
    }
}

// --- HTTP/1.0 client ---------------------------------------------------------

/// Perform an HTTP/1.0 GET. The full response (status line, headers, body) is
/// assembled into the netbuf `body` region. Returns `(status, body_offset,
/// total_len)` where the body is `body[body_offset..total_len]`.
fn http_get(
    dst_ip: [u8; 4],
    dst_mac: [u8; 6],
    port: u16,
    host: &str,
    path: &str,
) -> Option<(u16, usize, usize)> {
    let mut t = tcp_connect(dst_ip, dst_mac, port)?;

    // Build the request. HTTP/1.0 with an explicit close: the server writes the
    // whole body then FINs, which is our clean end-of-body signal.
    let mut req = [0u8; 512];
    let mut w = ReqWriter::new(&mut req);
    w.put(b"GET ");
    w.put(path.as_bytes());
    w.put(b" HTTP/1.0\r\nHost: ");
    w.put(host.as_bytes());
    w.put(b"\r\nUser-Agent: aurora/1.0\r\nConnection: close\r\n\r\n");
    let reqlen = w.len();
    tcp_send(&t, proto::TCP_PSH | proto::TCP_ACK, &req[..reqlen]);
    t.snd_nxt = t.snd_nxt.wrapping_add(reqlen as u32);

    let mut total = 0usize;
    let mut idle = 0;
    let mut got_fin = false;
    let mut seg = [0u8; 1600];
    loop {
        match tcp_poll(&t, &mut seg) {
            Some((seq, _ack, flags, dlen)) => {
                idle = 0;
                if flags & proto::TCP_RST != 0 {
                    break;
                }
                if dlen > 0 {
                    if seq == t.rcv_nxt {
                        // In-order data: append to the body region, bounded.
                        let room = BODY_MAX.saturating_sub(total);
                        let take = core::cmp::min(dlen, room);
                        unsafe {
                            let dst = (*nb()).body.as_mut_ptr().add(total);
                            core::ptr::copy_nonoverlapping(seg.as_ptr(), dst, take);
                        }
                        total += take;
                        t.rcv_nxt = t.rcv_nxt.wrapping_add(dlen as u32);
                    }
                    // Acknowledge (cumulative) either way.
                    tcp_send(&t, proto::TCP_ACK, &[]);
                }
                if flags & proto::TCP_FIN != 0 {
                    // The FIN consumes one sequence number if it is in order.
                    if seq.wrapping_add(dlen as u32) == t.rcv_nxt {
                        t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
                    }
                    tcp_send(&t, proto::TCP_ACK, &[]);
                    got_fin = true;
                    break;
                }
                if total >= BODY_MAX {
                    break;
                }
            }
            None => {
                idle += 1;
                if idle >= 6 {
                    break;
                }
            }
        }
    }

    // Send our FIN. If the peer already FINed we still send ours for a clean
    // close; otherwise this initiates the teardown.
    let _ = got_fin;
    tcp_close(&mut t);

    let resp = unsafe { &(&(*nb()).body)[..total] };
    let (status, body_off) = proto::parse_http_response(resp)?;
    Some((status, body_off, total))
}

// --- TLS 1.3 client ----------------------------------------------------------
//
// A from-scratch TLS 1.3 client (RFC 8446), one connection at a time, offering
// only TLS_CHACHA20_POLY1305_SHA256 with x25519 key exchange so it reuses the
// in-tree ChaCha20-Poly1305 AEAD, SHA-256/HKDF, and x25519. The pure protocol
// logic (key schedule, record framing, message parse/build) lives in `tls.rs`
// and is host-tested against the RFC 8448 trace; this drives it over the TCP
// client above. All session secrets live in the wiped `netbuf` region.

#[inline]
fn nb_tls() -> *mut TlsScratch {
    unsafe { addr_of_mut!((*nb()).tls) }
}

/// Pull one TCP segment and append in-order payload to the TLS stream buffer.
/// Returns `(made_progress, saw_fin)`.
fn tls_tcp_fill(t: &mut Tcp, stream_len: &mut usize) -> (bool, bool) {
    let mut seg = [0u8; 1600];
    match tcp_poll(t, &mut seg) {
        Some((seq, _ack, flags, dlen)) => {
            if flags & proto::TCP_RST != 0 {
                return (false, true);
            }
            let mut progress = false;
            if dlen > 0 {
                let ts = unsafe { &mut *nb_tls() };
                let room = TLS_STREAM_MAX.saturating_sub(*stream_len);
                if seq == t.rcv_nxt && dlen <= room {
                    ts.stream[*stream_len..*stream_len + dlen].copy_from_slice(&seg[..dlen]);
                    *stream_len += dlen;
                    t.rcv_nxt = t.rcv_nxt.wrapping_add(dlen as u32);
                    progress = true;
                }
                // Acknowledge our current cumulative sequence either way; a drop
                // (out of order or no room) is recovered by the peer retransmit.
                tcp_send(t, proto::TCP_ACK, &[]);
            }
            let mut fin = false;
            if flags & proto::TCP_FIN != 0 {
                if seq.wrapping_add(dlen as u32) == t.rcv_nxt {
                    t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
                }
                tcp_send(t, proto::TCP_ACK, &[]);
                fin = true;
                progress = true;
            }
            (progress, fin)
        }
        None => (false, false),
    }
}

/// Read exactly one TLS record into `nb().tls.rec`, consuming it from the stream
/// buffer. Returns the record length, or None on close/timeout/oversize.
fn tls_read_record(t: &mut Tcp, stream_len: &mut usize) -> Option<usize> {
    let mut idle = 0;
    let mut fin = false;
    loop {
        if *stream_len >= 5 {
            let ts = unsafe { &mut *nb_tls() };
            let len = ((ts.stream[3] as usize) << 8) | ts.stream[4] as usize;
            let total = 5 + len;
            if total > TLS_REC_MAX {
                return None;
            }
            if total <= *stream_len {
                ts.rec[..total].copy_from_slice(&ts.stream[..total]);
                ts.stream.copy_within(total..*stream_len, 0);
                *stream_len -= total;
                return Some(total);
            }
        }
        if fin {
            return None;
        }
        let (prog, f) = tls_tcp_fill(t, stream_len);
        if f {
            fin = true;
        }
        if prog {
            idle = 0;
        } else {
            idle += 1;
            if idle >= 12 {
                return None;
            }
        }
    }
}

/// Send a byte buffer over TCP as one or more PSH|ACK segments.
fn tls_tcp_send(t: &mut Tcp, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let n = core::cmp::min(1400, data.len() - off);
        tcp_send(t, proto::TCP_PSH | proto::TCP_ACK, &data[off..off + n]);
        t.snd_nxt = t.snd_nxt.wrapping_add(n as u32);
        off += n;
    }
}

/// Drain and process every complete handshake message currently buffered in
/// `nb().tls.hs_buf`, updating the transcript and TLS state. Returns Some(true)
/// once the server Finished has been verified, Some(false) if it needs more
/// bytes, or None on a fatal handshake error.
fn tls_process_handshake(hs_len: &mut usize, host: &str, insecure: bool) -> Option<bool> {
    loop {
        let (mtype, msg_total) = {
            let ts = unsafe { &*nb_tls() };
            if *hs_len < 4 {
                return Some(false);
            }
            let blen = ((ts.hs_buf[1] as usize) << 16)
                | ((ts.hs_buf[2] as usize) << 8)
                | ts.hs_buf[3] as usize;
            let total = 4 + blen;
            if total > TLS_HS_MAX {
                return None;
            }
            if *hs_len < total {
                return Some(false);
            }
            (ts.hs_buf[0], total)
        };

        let mut finished = false;
        match mtype {
            tls::HS_ENCRYPTED_EXTENSIONS => {
                let ts = unsafe { &mut *nb_tls() };
                ts.session.transcript.update(&ts.hs_buf[..msg_total]);
            }
            tls::HS_CERTIFICATE => {
                let ts = unsafe { &mut *nb_tls() };
                ts.session.transcript.update(&ts.hs_buf[..msg_total]);
                ts.session.subject_len = 0;
                ts.session.name_ok = false;
                ts.session.leaf_alg = 3;
                if let Some(der) = tls::certificate_leaf(&ts.hs_buf[..msg_total]) {
                    if let Some(cert) = x509::parse_certificate(der) {
                        if let Some(cn) = cert.subject_cn() {
                            let n = core::cmp::min(cn.len(), TLS_SUBJECT_MAX);
                            ts.session.subject[..n].copy_from_slice(&cn[..n]);
                            ts.session.subject_len = n;
                        }
                        ts.session.name_ok = match parse_ipv4(host) {
                            Some(ip) => cert.matches_ip(&ip),
                            None => cert.matches_dns(host),
                        };
                        ts.session.leaf_alg = match cert.spki_alg {
                            x509::SpkiAlg::Ed25519 => {
                                if cert.spki_key.len() == 32 {
                                    ts.session.leaf_pub.copy_from_slice(cert.spki_key);
                                }
                                0
                            }
                            x509::SpkiAlg::EcP256 => 1,
                            x509::SpkiAlg::Rsa => 2,
                            _ => 3,
                        };
                    }
                }
                ts.session.th_cert = ts.session.transcript.hash();
            }
            tls::HS_CERTIFICATE_VERIFY => {
                // Copy the pieces we need to the stack, then verify, then extend
                // the transcript. This keeps the borrows on `nb().tls` disjoint.
                let mut scheme = 0u16;
                let mut sig = [0u8; 64];
                let mut sig_len = 0usize;
                let (th, leaf_pub, alg, name_ok) = {
                    let ts = unsafe { &*nb_tls() };
                    if let Some((sc, s)) = tls::parse_certificate_verify(&ts.hs_buf[..msg_total]) {
                        scheme = sc;
                        sig_len = core::cmp::min(s.len(), 64);
                        sig[..sig_len].copy_from_slice(&s[..sig_len]);
                    }
                    (ts.session.th_cert, ts.session.leaf_pub, ts.session.leaf_alg, ts.session.name_ok)
                };
                let mut content = [0u8; 130];
                let clen = tls::certificate_verify_content(&th, &mut content);
                let verified = scheme == tls::SIG_ED25519
                    && alg == 0
                    && sig_len == 64
                    && ed25519::verify(&leaf_pub, &content[..clen], &sig);
                let level = if scheme == tls::SIG_ED25519 && alg == 0 {
                    // We can verify this scheme against the leaf key.
                    if verified && name_ok {
                        CertLevel::AuthenticatedToLeaf
                    } else if insecure {
                        CertLevel::InsecurePinned
                    } else {
                        // A genuine ed25519 authentication failure aborts.
                        return None;
                    }
                } else if insecure {
                    CertLevel::InsecurePinned
                } else {
                    // Scheme Aurora cannot verify yet (ECDSA/RSA): the channel is
                    // encrypted but the leaf binding is not proven. Stated plainly.
                    CertLevel::EncryptedUnverified
                };
                let ts = unsafe { &mut *nb_tls() };
                ts.session.sig_scheme = scheme;
                ts.session.leaf_verified = verified;
                ts.session.level = level;
                ts.session.transcript.update(&ts.hs_buf[..msg_total]);
            }
            tls::HS_FINISHED => {
                let mut vd = [0u8; 32];
                let mut vd_len = 0usize;
                let (th_before, s_secret) = {
                    let ts = unsafe { &*nb_tls() };
                    if let Some(v) = tls::parse_finished(&ts.hs_buf[..msg_total]) {
                        vd_len = core::cmp::min(v.len(), 32);
                        vd[..vd_len].copy_from_slice(&v[..vd_len]);
                    }
                    (ts.session.transcript.hash(), ts.session.s_hs_secret)
                };
                let expect = tls::finished_verify_data(&s_secret, &th_before);
                if vd_len != 32 || expect != vd {
                    return None;
                }
                let ts = unsafe { &mut *nb_tls() };
                ts.session.transcript.update(&ts.hs_buf[..msg_total]);
                finished = true;
            }
            _ => {
                let ts = unsafe { &mut *nb_tls() };
                ts.session.transcript.update(&ts.hs_buf[..msg_total]);
            }
        }

        // Remove the processed message from the front of the buffer.
        {
            let ts = unsafe { &mut *nb_tls() };
            ts.hs_buf.copy_within(msg_total..*hs_len, 0);
        }
        *hs_len -= msg_total;
        if finished {
            return Some(true);
        }
    }
}

/// Perform the full TLS 1.3 handshake and one HTTP/1.0 GET over the encrypted
/// channel. The decrypted response lands in the wiped `body` region; returns
/// `(status, body_offset, total_len)`. `insecure` relaxes certificate policy for
/// the deterministic local self-test (still runs the full handshake and record
/// layer). Negotiated facts are recorded in the session for `tlsinfo`.
fn https_get(
    dst_ip: [u8; 4],
    dst_mac: [u8; 6],
    port: u16,
    host: &str,
    path: &str,
    insecure: bool,
) -> Option<(u16, usize, usize)> {
    // Fresh ephemeral key material, all resident in the wiped netbuf session.
    let priv_key = entropy::session_key();
    let client_random = entropy::session_key();
    let session_id = entropy::session_key();
    let client_pub = x25519::x25519_base(&priv_key);
    {
        let s = unsafe { &mut (*nb()).tls.session };
        s.priv_key = priv_key;
        s.client_random = client_random;
        s.session_id = session_id;
        s.ks = tls::KeySchedule::new();
        s.transcript = tls::Transcript::new();
        s.level = CertLevel::EncryptedUnverified;
        s.leaf_verified = false;
        s.name_ok = false;
        s.sig_scheme = 0;
        s.subject_len = 0;
        s.cipher_suite = 0;
        s.group = 0;
        s.leaf_alg = 3;
    }

    let mut t = tcp_connect(dst_ip, dst_mac, port)?;
    let mut stream_len = 0usize;

    // ClientHello, as a plaintext handshake record.
    let mut ch = [0u8; 512];
    let chlen = tls::build_client_hello(&client_random, &session_id, &client_pub, host, &mut ch)?;
    unsafe { (*nb()).tls.session.transcript.update(&ch[..chlen]) };
    let mut chrec = [0u8; 5 + 512];
    chrec[0] = tls::CT_HANDSHAKE;
    chrec[1] = 0x03;
    chrec[2] = 0x03;
    chrec[3..5].copy_from_slice(&(chlen as u16).to_be_bytes());
    chrec[5..5 + chlen].copy_from_slice(&ch[..chlen]);
    tls_tcp_send(&mut t, &chrec[..5 + chlen]);

    // A single work budget for the whole exchange: a peer cannot make us process
    // an unbounded number of records (for example a ChangeCipherSpec flood that
    // the loops skip) regardless of what it sends. Every record read below is
    // charged, so no record type can be used to spin the core.
    let mut budget = tls::HandshakeBudget::new();

    // ServerHello (plaintext handshake record; skip any ChangeCipherSpec).
    let server_pub;
    loop {
        let total = tls_read_record(&mut t, &mut stream_len)?;
        if !budget.charge(total) {
            println!("[tls] handshake exceeded record/byte budget");
            return None;
        }
        let ts = unsafe { &mut *nb_tls() };
        if ts.rec[0] == tls::CT_CHANGE_CIPHER_SPEC {
            continue;
        }
        if ts.rec[0] != tls::CT_HANDSHAKE {
            return None;
        }
        let len = ((ts.rec[3] as usize) << 8) | ts.rec[4] as usize;
        ts.session.transcript.update(&ts.rec[5..5 + len]);
        let sh = tls::parse_server_hello(&ts.rec[5..5 + len])?;
        ts.session.cipher_suite = sh.cipher_suite;
        ts.session.group = sh.group;
        ts.session.server_pub = sh.server_pub;
        server_pub = sh.server_pub;
        break;
    }

    // Handshake secrets from the ECDHE shared value and the CH..SH transcript.
    let ecdhe = x25519::x25519(&priv_key, &server_pub);
    {
        let s = unsafe { &mut (*nb()).tls.session };
        s.ks.derive_handshake(&ecdhe);
        let th = s.transcript.hash();
        s.c_hs_secret = s.ks.client_hs_traffic(&th);
        s.s_hs_secret = s.ks.server_hs_traffic(&th);
        s.c_hs = TrafficKeys::from_secret(&s.c_hs_secret);
        s.s_hs = TrafficKeys::from_secret(&s.s_hs_secret);
    }

    // Read and process the encrypted handshake flight (EncryptedExtensions,
    // Certificate, CertificateVerify, Finished), possibly spanning records.
    let mut hs_len = 0usize;
    let mut done = false;
    while !done {
        let total = tls_read_record(&mut t, &mut stream_len)?;
        if !budget.charge(total) {
            println!("[tls] handshake exceeded record/byte budget");
            return None;
        }
        {
            let ts = unsafe { &mut *nb_tls() };
            match ts.rec[0] {
                tls::CT_CHANGE_CIPHER_SPEC => continue,
                tls::CT_APPLICATION_DATA => {
                    let (ct, plen) = tls::open_record(&mut ts.session.s_hs, &mut ts.rec[..total])?;
                    if ct == tls::CT_ALERT {
                        return None;
                    }
                    if ct != tls::CT_HANDSHAKE {
                        continue;
                    }
                    if hs_len + plen > TLS_HS_MAX {
                        return None;
                    }
                    let (a, b) = (hs_len, hs_len + plen);
                    let src = &ts.rec[5..5 + plen];
                    ts.hs_buf[a..b].copy_from_slice(src);
                    hs_len = b;
                }
                _ => return None,
            }
        }
        done = tls_process_handshake(&mut hs_len, host, insecure)?;
    }

    // Application traffic keys from the CH..server-Finished transcript.
    let th_sfin;
    {
        let s = unsafe { &mut (*nb()).tls.session };
        s.ks.derive_master();
        th_sfin = s.transcript.hash();
        let cap = s.ks.client_ap_traffic(&th_sfin);
        let sap = s.ks.server_ap_traffic(&th_sfin);
        s.c_ap = TrafficKeys::from_secret(&cap);
        s.s_ap = TrafficKeys::from_secret(&sap);
    }

    // Build the whole client flight into one buffer and send it as a single TCP
    // write: a plaintext ChangeCipherSpec (middlebox compat), the encrypted
    // client Finished under the client handshake keys, and the encrypted HTTP/1.0
    // GET under the client application keys. Sending one segment instead of three
    // shrinks the surface for a dropped segment on the polled, no-data-retransmit
    // TCP client.
    let mut flight = [0u8; 6 + (5 + 4 + 32 + 1 + 16) + (5 + 512 + 1 + 16)];
    let mut flen = 0;
    flight[..6].copy_from_slice(&[tls::CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
    flen += 6;
    {
        let c_secret = unsafe { (*nb()).tls.session.c_hs_secret };
        let vd = tls::finished_verify_data(&c_secret, &th_sfin);
        let mut fin_msg = [0u8; 4 + 32];
        fin_msg[0] = tls::HS_FINISHED;
        fin_msg[3] = 32;
        fin_msg[4..].copy_from_slice(&vd);
        let k = unsafe { &mut (*nb()).tls.session.c_hs };
        flen += tls::seal_record(k, tls::CT_HANDSHAKE, &fin_msg, &mut flight[flen..])?;
    }
    let mut req = [0u8; 512];
    let mut w = ReqWriter::new(&mut req);
    w.put(b"GET ");
    w.put(path.as_bytes());
    w.put(b" HTTP/1.0\r\nHost: ");
    w.put(host.as_bytes());
    w.put(b"\r\nUser-Agent: aurora-tls/1.0\r\nConnection: close\r\n\r\n");
    let reqlen = w.len();
    {
        let k = unsafe { &mut (*nb()).tls.session.c_ap };
        flen += tls::seal_record(k, tls::CT_APPLICATION_DATA, &req[..reqlen], &mut flight[flen..])?;
    }
    tls_tcp_send(&mut t, &flight[..flen]);

    // Read encrypted application records; decrypt into the wiped body region.
    // Post-handshake handshake messages (NewSessionTicket) are ignored.
    let mut total_body = 0usize;
    while let Some(rlen) = tls_read_record(&mut t, &mut stream_len) {
        if !budget.charge(rlen) {
            println!("[tls] exceeded post-handshake record/byte budget");
            break;
        }
        let ts = unsafe { &mut *nb_tls() };
        match ts.rec[0] {
            tls::CT_CHANGE_CIPHER_SPEC => continue,
            tls::CT_APPLICATION_DATA => {
                let (ct, plen) = match tls::open_record(&mut ts.session.s_ap, &mut ts.rec[..rlen]) {
                    Some(x) => x,
                    None => break,
                };
                match ct {
                    tls::CT_APPLICATION_DATA => {
                        let room = BODY_MAX.saturating_sub(total_body);
                        let take = core::cmp::min(plen, room);
                        unsafe {
                            let s = ts.rec.as_ptr().add(5);
                            let d = (*nb()).body.as_mut_ptr().add(total_body);
                            core::ptr::copy_nonoverlapping(s, d, take);
                        }
                        total_body += take;
                        if total_body >= BODY_MAX {
                            break;
                        }
                    }
                    tls::CT_ALERT => break,
                    _ => { /* NewSessionTicket / KeyUpdate: ignore */ }
                }
            }
            _ => break,
        }
    }

    tcp_close(&mut t);

    let resp = unsafe { &(&(*nb()).body)[..total_body] };
    let (status, body_off) = proto::parse_http_response(resp)?;
    Some((status, body_off, total_body))
}

fn cert_level_str(l: CertLevel) -> &'static str {
    match l {
        CertLevel::AuthenticatedToLeaf => "authenticated-to-leaf (CertificateVerify bound to leaf key + SNI matched)",
        CertLevel::EncryptedUnverified => "encrypted, leaf signature scheme not verified by Aurora",
        CertLevel::InsecurePinned => "insecure/pinned self-test mode",
    }
}

fn sig_scheme_str(s: u16) -> &'static str {
    match s {
        tls::SIG_ED25519 => "ed25519",
        tls::SIG_ECDSA_P256_SHA256 => "ecdsa_secp256r1_sha256",
        tls::SIG_RSA_PSS_RSAE_SHA256 => "rsa_pss_rsae_sha256",
        tls::SIG_RSA_PKCS1_SHA256 => "rsa_pkcs1_sha256",
        0 => "none",
        _ => "other",
    }
}

/// Print the negotiated TLS parameters recorded on the last handshake.
fn print_tls_info() {
    let s = unsafe { &(*nb()).tls.session };
    let suite = if s.cipher_suite == tls::TLS_CHACHA20_POLY1305_SHA256 {
        "TLS_CHACHA20_POLY1305_SHA256"
    } else {
        "unknown"
    };
    let group = if s.group == tls::GROUP_X25519 { "x25519" } else { "unknown" };
    println!("[tls] version: TLS 1.3");
    println!("[tls] cipher suite: {} ({:#06x})", suite, s.cipher_suite);
    println!("[tls] key exchange group: {} ({:#06x})", group, s.group);
    println!(
        "[tls] server CertificateVerify scheme: {} ({:#06x}), leaf signature verified: {}",
        sig_scheme_str(s.sig_scheme),
        s.sig_scheme,
        s.leaf_verified
    );
    if s.subject_len > 0 {
        let subj = core::str::from_utf8(&s.subject[..s.subject_len]).unwrap_or("<binary>");
        println!("[tls] certificate subject CN: {}", subj);
    } else {
        println!("[tls] certificate subject CN: <none>");
    }
    println!("[tls] validation level: {}", cert_level_str(s.level));
}

// --- Shell entry points ------------------------------------------------------

/// Parse `dotted` as an IPv4 address, e.g. "10.0.2.2".
fn parse_ipv4(dotted: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = dotted.split('.');
    for o in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 {
            return None;
        }
        *o = p.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Split `scheme://host[:port]/path` for http and https. Returns
/// `(is_tls, host, port, path)` with the default port per scheme.
fn parse_url_scheme(url: &str) -> Option<(bool, &str, u16, &str)> {
    let (tls, rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (true, r, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r, 80u16)
    } else {
        return None;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (&authority[..i], authority[i + 1..].parse::<u16>().ok()?),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((tls, host, port, path))
}

/// Resolve a URL host to an IPv4 address: dotted-decimal is used directly, a name
/// goes through DNS on the default nameserver.
fn resolve_host(host: &str) -> Option<[u8; 4]> {
    if let Some(ip) = parse_ipv4(host) {
        return Some(ip);
    }
    resolve(host, DEFAULT_NS)
}

fn print_ip(ip: [u8; 4]) {
    print!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

/// Count occurrences of `needle` across the whole netbuf region.
fn scan_netbuf(needle: &[u8]) -> u64 {
    let (start, end) = mem::netbuf_region_range();
    let n = needle.len();
    if n == 0 || end - start < n {
        return 0;
    }
    let first = needle[0];
    let mut count = 0u64;
    let mut p = start;
    let last = end - n;
    while p <= last {
        if unsafe { core::ptr::read_volatile(p as *const u8) } == first {
            let mut ok = true;
            for (i, &nb) in needle.iter().enumerate().skip(1) {
                if unsafe { core::ptr::read_volatile((p + i) as *const u8) } != nb {
                    ok = false;
                    break;
                }
            }
            if ok {
                count += 1;
            }
        }
        p += 1;
    }
    count
}

/// `fetch [-k] <url>`: resolve, connect, GET, and print the status and body. An
/// `https://` URL runs the from-scratch TLS 1.3 client over TCP 443; `-k` selects
/// the insecure/pinned mode for the deterministic local self-test.
pub fn shell_fetch(args: &str) {
    if !crate::session::has_net() {
        println!("[net] denied: session inactive or missing CAP_NET (try 'cap net')");
        return;
    }
    if !init() {
        println!("[net] device unavailable");
        return;
    }
    let (insecure, url) = match args.strip_prefix("-k") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, args),
    };
    let (is_tls, host, port, path) = match parse_url_scheme(url) {
        Some(x) => x,
        None => {
            println!("[fetch] bad url (expected http(s)://host[:port]/path)");
            return;
        }
    };
    let scheme = if is_tls { "https" } else { "http" };
    print!("[fetch] GET {}://{}:{}{} -> resolving {} ... ", scheme, host, port, path, host);
    let ip = match resolve_host(host) {
        Some(ip) => {
            print_ip(ip);
            println!();
            ip
        }
        None => {
            println!("FAILED (dns)");
            return;
        }
    };
    let mac = match next_hop_mac(ip) {
        Some(m) => m,
        None => {
            println!("[fetch] ARP failed for next hop");
            return;
        }
    };
    let result = if is_tls {
        https_get(ip, mac, port, host, path, insecure)
    } else {
        http_get(ip, mac, port, host, path)
    };
    match result {
        Some((status, body_off, total)) => {
            if is_tls {
                print_tls_info();
            }
            let body_len = total.saturating_sub(body_off);
            println!("[fetch] HTTP status: {}, body {} bytes", status, body_len);
            // Print a bounded slice of the body so a large response cannot flood
            // the console. The body lives in the netbuf region, scrubbed on wipe.
            let show = core::cmp::min(body_len, 1024);
            print!("[fetch] body: ");
            let body = unsafe { &(&(*nb()).body)[body_off..body_off + show] };
            match core::str::from_utf8(body) {
                Ok(s) => print!("{}", s),
                Err(_) => {
                    for b in body {
                        print!("{:02x}", b);
                    }
                }
            }
            println!();
        }
        None => {
            if is_tls && insecure {
                println!("[fetch] request failed. -k relaxes the certificate check but still needs a TLS 1.3 peer that offers TLS_CHACHA20_POLY1305_SHA256 with x25519 (the bundled local self-test server provides one)");
            } else {
                println!("[fetch] request failed (no response / TLS or HTTP error)");
            }
        }
    }
}

/// `tlsinfo [-k] <https-url|host>`: run a TLS 1.3 handshake and print the
/// negotiated group, cipher suite, certificate subject, and validation level.
pub fn shell_tlsinfo(args: &str) {
    if !crate::session::has_net() {
        println!("[net] denied: session inactive or missing CAP_NET (try 'cap net')");
        return;
    }
    if !init() {
        println!("[net] device unavailable");
        return;
    }
    let (insecure, rest) = match args.strip_prefix("-k") {
        Some(r) => (true, r.trim_start()),
        None => (false, args),
    };
    // Accept a bare host or a full https URL.
    let (host, port, path) = if rest.starts_with("http") {
        match parse_url_scheme(rest) {
            Some((_, h, p, pa)) => (h, p, pa),
            None => {
                println!("[tlsinfo] bad url");
                return;
            }
        }
    } else {
        (rest, 443u16, "/")
    };
    print!("[tlsinfo] handshaking with {}:{} ... ", host, port);
    let ip = match resolve_host(host) {
        Some(ip) => {
            print_ip(ip);
            println!();
            ip
        }
        None => {
            println!("FAILED (dns)");
            return;
        }
    };
    let mac = match next_hop_mac(ip) {
        Some(m) => m,
        None => {
            println!("[tlsinfo] ARP failed for next hop");
            return;
        }
    };
    match https_get(ip, mac, port, host, path, insecure) {
        Some((status, _off, _total)) => {
            print_tls_info();
            println!("[tlsinfo] handshake ok, server answered HTTP {}", status);
        }
        None => {
            if insecure {
                println!("[tlsinfo] handshake failed. -k relaxes the certificate check but still needs a TLS 1.3 peer that offers TLS_CHACHA20_POLY1305_SHA256 with x25519 (the bundled local self-test server provides one)");
            } else {
                println!("[tlsinfo] handshake failed");
            }
        }
    }
}

/// `resolve <name> [ns-ip]`: best-effort live DNS lookup that prints the A record.
pub fn shell_resolve(args: &str) {
    if !crate::session::has_net() {
        println!("[net] denied: session inactive or missing CAP_NET (try 'cap net')");
        return;
    }
    let mut it = args.split_whitespace();
    let name = match it.next() {
        Some(n) => n,
        None => {
            println!("usage: resolve <name> [nameserver-ip]");
            return;
        }
    };
    let ns = it.next().and_then(parse_ipv4).unwrap_or(DEFAULT_NS);
    print!("[dns] resolving {} via ", name);
    print_ip(ns);
    print!(" ... ");
    match resolve(name, ns) {
        Some(ip) => {
            print!("A record ");
            print_ip(ip);
            println!(" (live DNS ok)");
        }
        None => println!("no answer (offline or no record); not a gate failure"),
    }
}

/// `netamnesia <url>`: fetch a payload carrying a known sentinel into the network
/// buffers, confirm it is present, wipe, then prove the sentinel is gone from the
/// whole netbuf region. This extends the amnesia proof to fetched network bytes.
pub fn shell_netamnesia(args: &str) {
    if !crate::session::has_net() {
        println!("[net] denied: session inactive or missing CAP_NET (try 'cap net')");
        return;
    }
    if !init() {
        println!("[net] device unavailable");
        return;
    }
    let (insecure, url) = match args.strip_prefix("-k") {
        Some(r) => (true, r.trim_start()),
        None => (false, args),
    };
    println!("[netamnesia] === proving fetched network bytes do not survive a wipe ===");
    let (is_tls, host, port, path) = match parse_url_scheme(url) {
        Some(x) => x,
        None => {
            println!("[netamnesia] bad url");
            return;
        }
    };
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            println!("[netamnesia] resolve failed");
            return;
        }
    };
    let mac = match next_hop_mac(ip) {
        Some(m) => m,
        None => {
            println!("[netamnesia] ARP failed");
            return;
        }
    };
    let result = if is_tls {
        https_get(ip, mac, port, host, path, insecure)
    } else {
        http_get(ip, mac, port, host, path)
    };
    if is_tls {
        println!("[netamnesia] fetched over TLS 1.3; the decrypted body lives in the wiped netbuf region");
    }
    let (status, body_off, total) = match result {
        Some(x) => x,
        None => {
            if is_tls && insecure {
                println!("[netamnesia] FAIL: TLS 1.3 handshake failed. -k relaxes the certificate check but still needs a TLS 1.3 peer that offers TLS_CHACHA20_POLY1305_SHA256 with x25519 (the bundled local self-test server provides one)");
            } else {
                println!("[netamnesia] FAIL: fetch returned no response");
            }
            return;
        }
    };
    let body_len = total.saturating_sub(body_off);
    if body_len == 0 {
        println!(
            "[netamnesia] fetch returned 0 body bytes (status {}); nothing to prove, skipping",
            status
        );
        return;
    }
    // Fingerprint the REAL fetched bytes: a contiguous slice of the actual
    // response body, taken from the netbuf `body` region where it now lives.
    // Copy it into this (live, above-SP) stack frame so the marker itself
    // survives the wipe, which only scrubs the stack below the current SP.
    let fp_len = core::cmp::min(body_len, 32);
    let mut fp = [0u8; 32];
    unsafe {
        let src = (*nb()).body.as_ptr().add(body_off);
        core::ptr::copy_nonoverlapping(src, fp.as_mut_ptr(), fp_len);
    }
    let fp = &fp[..fp_len];
    let pre = scan_netbuf(fp);
    println!(
        "[netamnesia] fetched {} body bytes (status {}); {}-byte real-body fingerprint present {} time(s) in the network buffers before wipe",
        body_len, status, fp_len, pre
    );
    if pre == 0 {
        println!("[netamnesia] FAIL: real fetched bytes not found in the netbuf region (route/buffer wrong)");
        return;
    }
    crate::wipe::wipe_and_report();
    let post = scan_netbuf(fp);
    println!(
        "[netamnesia] post-wipe scan: real-body fingerprint present {} time(s) in the network buffers",
        post
    );
    if post == 0 {
        println!("[netamnesia] PASS: real fetched network bytes scrubbed, fingerprint fully gone");
    } else {
        println!("[netamnesia] FAIL: fetched bytes survived the wipe");
    }
}

/// Small fixed-buffer writer for building the HTTP request without the heap.
struct ReqWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ReqWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn put(&mut self, bytes: &[u8]) {
        let n = core::cmp::min(bytes.len(), self.buf.len() - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
    }
    fn len(&self) -> usize {
        self.pos
    }
}

/// Shell entry: bring the NIC up (requires CAP_NET), resolve the gateway by ARP,
/// then round-trip `msg` as an ICMP echo payload and report the echoed result.
pub fn shell_roundtrip(msg: &str) {
    if !crate::session::has_net() {
        println!("[net] denied: session inactive or missing CAP_NET (try 'cap net')");
        return;
    }
    if !init() {
        println!("[net] device unavailable");
        return;
    }
    println!("[net] resolving gateway {}.{}.{}.{} via ARP...", GW_IP[0], GW_IP[1], GW_IP[2], GW_IP[3]);
    let gw = match arp_resolve(GW_IP) {
        Some(g) => {
            println!(
                "[net] ARP reply: gateway is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (round trip ok)",
                g[0], g[1], g[2], g[3], g[4], g[5]
            );
            g
        }
        None => {
            println!("[net] ARP round trip FAILED (no reply)");
            return;
        }
    };
    let token = msg.as_bytes();
    match icmp_echo(gw, token) {
        Some(echoed) => {
            let n = core::cmp::min(token.len(), 16);
            let ok = echoed[..n] == token[..n];
            let text = core::str::from_utf8(&echoed[..n]).unwrap_or("<binary>");
            println!("[net] ICMP echo reply received: \"{}\" (payload match: {})", text, ok);
            if ok {
                println!("[net] round trip complete: sent a task and received the result back");
            }
        }
        None => println!("[net] ICMP echo round trip FAILED (no reply)"),
    }
}
