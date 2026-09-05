//! A from-scratch virtio-net driver and a minimal Ethernet / ARP / IPv4 / ICMP
//! stack: Aurora's revocable workload I/O channel.
//!
//! The device is a modern (version 2) virtio-mmio virtio-net NIC on the QEMU
//! `virt` machine, attached with `-netdev user,... -device virtio-net-device`.
//! The driver brings the device up (reset, feature negotiation for VERSION_1 and
//! MAC, split virtqueues), then the stack does a real request/response round
//! trip over QEMU's user-mode network: an ARP request resolves the gateway, and
//! an ICMP echo carries a token to the gateway and back. That is enough for an
//! agent to send data out and get a result in without a human on the UART.
//!
//! All of this is gated by CAP_NET, which is off by default and revocable, so the
//! trace-free posture holds unless a session explicitly asks for the network.
//!
//! Zero external crates. Polling only (no NIC IRQ), which is all a request/reply
//! round trip needs. Cache maintenance is elided because QEMU TCG has no cache
//! between the CPU and the emulated DMA; barriers order the ring updates.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{compiler_fence, Ordering};

use crate::println;

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

impl Queue {
    const fn new() -> Self {
        Queue {
            desc: [VqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QSIZE],
            avail: VqAvail { flags: 0, idx: 0, ring: [0; QSIZE], used_event: 0 },
            used: VqUsed {
                flags: 0,
                idx: 0,
                ring: [VqUsedElem { id: 0, len: 0 }; QSIZE],
                avail_event: 0,
            },
        }
    }
}

#[repr(C, align(4096))]
struct Buf([u8; BUF_SIZE]);

static mut RXQ: Queue = Queue::new();
static mut TXQ: Queue = Queue::new();
static mut RX_BUFS: [Buf; QSIZE] = [const { Buf([0; BUF_SIZE]) }; QSIZE];
static mut TX_BUF: Buf = Buf([0; BUF_SIZE]);

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
        let q = addr_of_mut!(RXQ);
        let buf = addr_of!(RX_BUFS[i]) as u64;
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

    if !setup_queue(base, 0, addr_of_mut!(RXQ)) || !setup_queue(base, 1, addr_of_mut!(TXQ)) {
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

/// Transmit one Ethernet frame (already including dst/src MAC + ethertype).
fn send_frame(frame: &[u8]) {
    let base = unsafe { NET.base };
    unsafe {
        let tx = addr_of_mut!(TXQ);
        let buf = addr_of_mut!(TX_BUF.0) as *mut u8;
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
            let rx = addr_of_mut!(RXQ);
            let used_idx = core::ptr::read_volatile(addr_of!((*rx).used.idx));
            let seen = NET.rx_used_seen;
            if used_idx != seen {
                let slot = (seen as usize) % QSIZE;
                let elem = core::ptr::read_volatile(addr_of!((*rx).used.ring[slot]));
                let id = elem.id as usize % QSIZE;
                let total = elem.len as usize;
                let frame_len = total.saturating_sub(NET_HDR_LEN);
                let src = addr_of!(RX_BUFS[id].0) as *const u8;
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

/// Send an ARP request for `GW_IP` and wait for the reply, returning the
/// gateway's MAC. This is a genuine TX+RX round trip through the virtual network.
fn arp_resolve_gateway() -> Option<[u8; 6]> {
    let mac = our_mac();
    let mut f = [0u8; 42];
    // Ethernet header.
    f[0..6].copy_from_slice(&BROADCAST);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ET_ARP.to_be_bytes());
    // ARP payload.
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // htype ethernet
    f[16..18].copy_from_slice(&ET_IPV4.to_be_bytes()); // ptype IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&1u16.to_be_bytes()); // op request
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&OUR_IP);
    f[32..38].copy_from_slice(&[0u8; 6]);
    f[38..42].copy_from_slice(&GW_IP);
    send_frame(&f);

    let mut buf = [0u8; BUF_SIZE];
    for _ in 0..8 {
        let n = recv_frame(&mut buf)?;
        if n >= 42 {
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            let op = u16::from_be_bytes([buf[20], buf[21]]);
            if et == ET_ARP && op == 2 && buf[28..32] == GW_IP {
                let mut gw = [0u8; 6];
                gw.copy_from_slice(&buf[22..28]);
                return Some(gw);
            }
        }
    }
    None
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Send an ICMP echo request carrying `token` to the gateway and wait for the
/// echo reply, returning the echoed token bytes. A real request/response with a
/// payload: an agent sends data out and gets a result back.
fn icmp_echo(gw: [u8; 6], token: &[u8]) -> Option<[u8; 16]> {
    let mac = our_mac();
    let payload_len = core::cmp::min(token.len(), 16);
    let icmp_len = 8 + payload_len; // ICMP header + payload
    let ip_total = 20 + icmp_len;
    let frame_len = 14 + ip_total;

    let mut f = [0u8; 14 + 20 + 8 + 16];
    // Ethernet.
    f[0..6].copy_from_slice(&gw);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ET_IPV4.to_be_bytes());
    // IPv4 header.
    f[14] = 0x45; // version 4, IHL 5
    f[15] = 0;
    f[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    f[18..20].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    f[20..22].copy_from_slice(&0u16.to_be_bytes()); // flags/frag
    f[22] = 64; // TTL
    f[23] = 1; // protocol ICMP
    // checksum (24..26) zero for now
    f[26..30].copy_from_slice(&OUR_IP);
    f[30..34].copy_from_slice(&GW_IP);
    let ipcsum = ip_checksum(&f[14..34]);
    f[24..26].copy_from_slice(&ipcsum.to_be_bytes());
    // ICMP echo request.
    let icmp = 34;
    f[icmp] = 8; // type echo request
    f[icmp + 1] = 0; // code
    // checksum icmp+2..icmp+4 zero for now
    f[icmp + 4..icmp + 6].copy_from_slice(&0xABCDu16.to_be_bytes()); // id
    f[icmp + 6..icmp + 8].copy_from_slice(&1u16.to_be_bytes()); // seq
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
                    // echo reply
                    let mut echoed = [0u8; 16];
                    echoed[..payload_len].copy_from_slice(&buf[icmp + 8..icmp + 8 + payload_len]);
                    return Some(echoed);
                }
            }
        }
    }
    None
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
    let gw = match arp_resolve_gateway() {
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
            println!(
                "[net] ICMP echo reply received: \"{}\" (payload match: {})",
                text, ok
            );
            if ok {
                println!("[net] round trip complete: sent a task and received the result back");
            }
        }
        None => println!("[net] ICMP echo round trip FAILED (no reply)"),
    }
}
