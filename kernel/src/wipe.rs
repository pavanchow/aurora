//! Panic wipe / kill switch.
//!
//! `wipe()` scrubs the session's reachable RAM in order of value: the session
//! key dies first, then the vault region, then the whole physical frame pool.
//! Every byte is overwritten with zeros through volatile writes so the compiler
//! cannot elide the scrub, and the data cache is then cleaned and invalidated so
//! no plaintext survives in a dirty cache line. The elapsed time is measured
//! with the cycle-resolution generic timer counter and reported, to show the
//! wipe is fast. It is reachable from the `wipe` shell command, the `wipe`
//! syscall, the kernel panic handler, and normal shutdown.
//!
//! Scope: this scrubs the RAM Aurora manages as session working memory (the
//! vault region, the frame pool, and the network scratch region that holds the
//! virtio rings, receive buffers, and any fetched HTTP body), the key, and the
//! free part of the kernel stack below the current stack pointer, where
//! decrypted secrets or fetched bytes that transited a now-returned frame would
//! otherwise linger. It does not scrub the live
//! frames above the current stack pointer (this wipe's own frames), the code, or
//! the in-use heap while the kernel is still running on them. A physical attacker
//! with cold-boot or DMA access is out of scope, see DESIGN.md.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::{mem, net, println, session};

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

#[inline]
fn sp_now() -> usize {
    let v: usize;
    unsafe { core::arch::asm!("mov {}, sp", out(reg) v, options(nomem, nostack)) };
    v
}

#[inline]
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Overwrite `[start, end)` with zeros via volatile 8-byte writes.
fn scrub(start: usize, end: usize) {
    let mut p = start;
    while p + 8 <= end {
        unsafe { core::ptr::write_volatile(p as *mut u64, 0) };
        p += 8;
    }
    while p < end {
        unsafe { core::ptr::write_volatile(p as *mut u8, 0) };
        p += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Clean and invalidate the data cache over `[start, end)` so the zeros reach
/// RAM and no stale plaintext line survives. 64-byte cache lines on cortex-a72.
fn clean_invalidate(start: usize, end: usize) {
    const LINE: usize = 64;
    let mut p = start & !(LINE - 1);
    while p < end {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) p, options(nostack)) };
        p += LINE;
    }
    unsafe { core::arch::asm!("dsb ish", "isb", options(nostack)) };
}

pub struct WipeReport {
    pub bytes: usize,
    pub cycles: u64,
    pub freq_hz: u64,
}

impl WipeReport {
    pub fn micros(&self) -> u64 {
        self.cycles
            .saturating_mul(1_000_000)
            .checked_div(self.freq_hz)
            .unwrap_or(0)
    }
}

/// Scrub all reachable session RAM. Key first, then vault, then frame pool.
pub fn wipe() -> WipeReport {
    let start = cntpct();

    // 1. Key material dies first.
    let key_bytes = session::zero_key_first();

    // 2. Vault region.
    let (vs, ve) = mem::vault_region_range();
    scrub(vs, ve);

    // 3. Entire physical frame pool.
    let (fs, fe) = mem::frame_pool_range();
    scrub(fs, fe);

    // 3b. The network scratch region: virtio rings, receive buffers, and the
    // fetched HTTP body, so no byte pulled off the network survives a wipe. The
    // NIC is marked down first so a later network use re-initializes cleanly
    // instead of trusting the now-zeroed rings.
    net::on_wipe();
    let (ns, ne) = mem::netbuf_region_range();
    scrub(ns, ne);

    // 4. The free part of the kernel stack, below the current stack pointer.
    // Decrypted vault plaintext and other secrets that transited a now-returned
    // stack frame live here; the live frames above SP (this wipe's own frames)
    // are left untouched. Leave a small guard below SP so the scrub loop's own
    // stack use is never overwritten mid-flight.
    let (sb, st) = mem::stack_region_range();
    let sp = sp_now();
    // When the wipe runs on the main kernel stack, scrub the free part below the
    // live frames. When it runs from a fault on the dedicated exception stack, the
    // whole main stack is free (nothing is running on it), so scrub it entirely,
    // which also covers anything an overflow scribbled near the bottom.
    let se = if sp > sb && sp <= st {
        (sp.saturating_sub(256)) & !0xF
    } else {
        st
    };
    let stack_bytes = se.saturating_sub(sb);
    if stack_bytes > 0 {
        scrub(sb, se);
    }

    // 5. Push the zeros past the cache into RAM.
    clean_invalidate(vs, ve);
    clean_invalidate(fs, fe);
    clean_invalidate(ns, ne);
    if stack_bytes > 0 {
        clean_invalidate(sb, se);
    }

    // 6. Forget session metadata.
    session::teardown();

    let cycles = cntpct().wrapping_sub(start);
    let bytes = key_bytes + (ve - vs) + (fe - fs) + (ne - ns) + stack_bytes;
    WipeReport { bytes, cycles, freq_hz: cntfrq() }
}

/// Wipe and print a one-line report. Shared by the shell, syscall, and shutdown.
pub fn wipe_and_report() -> WipeReport {
    let r = wipe();
    println!(
        "[wipe] scrubbed {} bytes (key+vault+frames+net+stack) in {} cycles ({} us at {} Hz), caches flushed",
        r.bytes,
        r.cycles,
        r.micros(),
        r.freq_hz
    );
    r
}
