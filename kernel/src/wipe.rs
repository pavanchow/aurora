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
//! Honest scope: this scrubs the RAM Aurora manages as session working memory
//! (the vault region and the frame pool) plus the key. It does not scrub the
//! live kernel stack, code, or in-use heap while the kernel is still running on
//! them. A physical attacker with cold-boot or DMA access is out of scope, see
//! DESIGN.md.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::{mem, println, session};

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
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

    // 4. Push the zeros past the cache into RAM.
    clean_invalidate(vs, ve);
    clean_invalidate(fs, fe);

    // 5. Forget session metadata.
    session::teardown();

    let cycles = cntpct().wrapping_sub(start);
    let bytes = key_bytes + (ve - vs) + (fe - fs);
    WipeReport { bytes, cycles, freq_hz: cntfrq() }
}

/// Wipe and print a one-line report. Shared by the shell, syscall, and shutdown.
pub fn wipe_and_report() -> WipeReport {
    let r = wipe();
    println!(
        "[wipe] scrubbed {} bytes (key+vault+frames) in {} cycles ({} us at {} Hz), caches flushed",
        r.bytes,
        r.cycles,
        r.micros(),
        r.freq_hz
    );
    r
}
