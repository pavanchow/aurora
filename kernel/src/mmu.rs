//! Virtual memory. Builds a single level-1 translation table of 1 GiB blocks
//! (identity mapped: device memory below 1 GiB, normal RAM above), installs it in
//! TTBR0_EL1, and turns on the MMU plus caches via SCTLR_EL1.

use core::ptr::addr_of;

use crate::ptable::{self, block_1g, ENTRIES};

#[repr(C, align(4096))]
struct PageTable([u64; ENTRIES]);

#[link_section = ".bss.pagetables"]
static mut L1: PageTable = PageTable([0; ENTRIES]);

pub fn init() {
    unsafe {
        let l1 = addr_of!(L1) as *mut u64;

        // Block 0 (0x0000_0000..0x4000_0000): device MMIO (UART, GIC, ...).
        *l1.add(0) = block_1g(0x0000_0000, true);
        // Blocks 1..4 (0x4000_0000..0x1_0000_0000): normal cacheable RAM.
        *l1.add(1) = block_1g(0x4000_0000, false);
        *l1.add(2) = block_1g(0x8000_0000, false);
        *l1.add(3) = block_1g(0xC000_0000, false);

        core::arch::asm!(
            "msr mair_el1, {mair}",
            "msr tcr_el1,  {tcr}",
            "msr ttbr0_el1, {ttbr}",
            "isb",
            mair = in(reg) ptable::mair_value(),
            tcr  = in(reg) ptable::tcr_value(),
            ttbr = in(reg) l1 as u64,
        );

        // Invalidate TLBs before enabling translation.
        core::arch::asm!("tlbi vmalle1", "dsb ish", "isb");

        // Enable MMU (M), data cache (C), instruction cache (I).
        let mut sctlr: u64;
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12);
        core::arch::asm!("msr sctlr_el1, {}", "isb", in(reg) sctlr);
    }
}

/// True once translation is on; read back SCTLR_EL1.M.
pub fn is_enabled() -> bool {
    let sctlr: u64;
    unsafe { core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr) };
    sctlr & 1 != 0
}
