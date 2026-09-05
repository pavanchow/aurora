//! ARM generic timer (EL1 physical timer) driving periodic scheduler ticks.
//! On QEMU `virt` the non-secure EL1 physical timer raises PPI 14 = INTID 30.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::gic;

pub const TIMER_INTID: u32 = 30;
pub const TICK_HZ: u64 = 100;

static TICKS: AtomicU64 = AtomicU64::new(0);
static INTERVAL: AtomicU64 = AtomicU64::new(0);

#[inline]
fn read_cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v) };
    v
}

#[inline]
fn write_tval(v: u64) {
    unsafe { core::arch::asm!("msr cntp_tval_el0, {}", in(reg) v) };
}

#[inline]
fn write_ctl(v: u64) {
    unsafe { core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) v) };
}

pub fn init() {
    let freq = read_cntfrq();
    let interval = freq / TICK_HZ;
    INTERVAL.store(interval, Ordering::Relaxed);
    write_tval(interval);
    write_ctl(1); // enable, IMASK=0
    gic::enable(TIMER_INTID);
}

/// Called from the IRQ handler: reload the countdown and count the tick.
pub fn on_tick() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    write_tval(interval);
    TICKS.fetch_add(1, Ordering::Relaxed);
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    ticks() * (1000 / TICK_HZ)
}
