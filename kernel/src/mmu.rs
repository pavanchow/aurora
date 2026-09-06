//! Virtual memory. Builds a single level-1 translation table of 1 GiB blocks
//! (identity mapped: device memory below 1 GiB, normal RAM above), then refines
//! the one 1 GiB block that contains the dedicated EL0 user region down to a
//! level-2 table of 2 MiB blocks and a level-3 table of 4 KiB pages, so exactly
//! the user code and stack pages are EL0-accessible while everything else,
//! including the vault and the session key, stays EL1-only. Installs the table
//! in TTBR0_EL1 and turns on the MMU plus caches via SCTLR_EL1.

use core::ptr::addr_of;

use crate::ptable::{self, block_1g, block_2m, page_4k, table_desc, BLOCK_1G, BLOCK_2M, ENTRIES, PAGE_SIZE};

#[repr(C, align(4096))]
struct PageTable([u64; ENTRIES]);

#[link_section = ".bss.pagetables"]
static mut L1: PageTable = PageTable([0; ENTRIES]);

// Refinement tables for the 1 GiB block and the 2 MiB region that hold the EL0
// user pages.
#[link_section = ".bss.pagetables"]
static mut L2_USER: PageTable = PageTable([0; ENTRIES]);
#[link_section = ".bss.pagetables"]
static mut L3_USER: PageTable = PageTable([0; ENTRIES]);

// Refinement table for the 2 MiB region that holds the stack guard page, so that
// one 4 KiB page can be left unmapped while the surrounding heap and stack pages
// stay identity-mapped.
#[link_section = ".bss.pagetables"]
static mut L3_GUARD: PageTable = PageTable([0; ENTRIES]);

extern "C" {
    static __user_start: u8;
    static __guard_start: u8;
}

/// Address of the unmapped stack guard page.
fn guard_page_addr() -> usize {
    addr_of!(__guard_start) as usize
}

/// Address of the EL0 user code page (page 0 of the user region).
pub fn user_code_addr() -> usize {
    addr_of!(__user_start) as usize
}

/// Address of the EL0 user stack page (page 1 of the user region).
pub fn user_stack_page() -> usize {
    user_code_addr() + PAGE_SIZE
}

/// Top of the EL0 user stack (the stack grows down from the end of page 1).
pub fn user_stack_top() -> usize {
    user_stack_page() + PAGE_SIZE
}

/// The EL0-accessible user region `[start, end)`: the user code page and the user
/// stack page, contiguous. A syscall pointer+len supplied by an EL0 task must lie
/// wholly inside this range (see `uaccess` and `syscall::dispatch`).
pub fn user_region_range() -> (usize, usize) {
    (user_code_addr(), user_stack_top())
}

pub fn init() {
    unsafe {
        let l1 = addr_of!(L1) as *mut u64;

        // Block 0 (0x0000_0000..0x4000_0000): device MMIO (UART, GIC, ...).
        *l1.add(0) = block_1g(0x0000_0000, true);
        // Blocks 1..4 (0x4000_0000..0x1_0000_0000): normal cacheable RAM.
        *l1.add(1) = block_1g(0x4000_0000, false);
        *l1.add(2) = block_1g(0x8000_0000, false);
        *l1.add(3) = block_1g(0xC000_0000, false);

        refine_user_mapping(l1);
        refine_guard_mapping();

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

/// Refine the 1 GiB block that holds the user region into a level-2 table of
/// 2 MiB blocks, and the single 2 MiB region holding the user pages into a
/// level-3 table of 4 KiB pages. All entries keep the identity mapping and stay
/// EL1-only, except the user code page (EL0 read/execute) and the user stack
/// page (EL0 read/write). Done before the MMU is enabled, so no break-before-make
/// dance is needed.
unsafe fn refine_user_mapping(l1: *mut u64) {
    let user = user_code_addr();
    let l1i = ptable::l1_index(user);
    let l2i = ptable::l2_index(user);

    let l2 = addr_of!(L2_USER) as *mut u64;
    let l3 = addr_of!(L3_USER) as *mut u64;

    // Identity-map the whole 1 GiB block as 2 MiB EL1 blocks.
    let block_base = l1i * BLOCK_1G;
    for i in 0..ENTRIES {
        *l2.add(i) = block_2m(block_base + i * BLOCK_2M, false);
    }

    // Identity-map the user 2 MiB as EL1-only 4 KiB pages, then open exactly the
    // two user pages to EL0.
    let region_base = user & !(BLOCK_2M - 1);
    for i in 0..ENTRIES {
        *l3.add(i) = page_4k(region_base + i * PAGE_SIZE, false, false);
    }
    let code = user_code_addr();
    let stack = user_stack_page();
    *l3.add(ptable::l3_index(code)) = page_4k(code, true, true);
    *l3.add(ptable::l3_index(stack)) = page_4k(stack, true, false);

    // Link L3 into L2 and L2 into L1.
    *l2.add(l2i) = table_desc(l3 as usize);
    *l1.add(l1i) = table_desc(l2 as usize);
}

/// Refine the 2 MiB block that holds the stack guard page into a level-3 table of
/// 4 KiB pages, all identity-mapped EL1-only except the single guard page, which
/// is left invalid (unmapped). The guard page lives in the same 1 GiB block as the
/// user region, so it refines the same level-2 table `refine_user_mapping` built;
/// it must therefore run after it. Done before the MMU is enabled, so no
/// break-before-make dance is needed.
unsafe fn refine_guard_mapping() {
    let guard = guard_page_addr();
    let l2 = addr_of!(L2_USER) as *mut u64;
    let l3 = addr_of!(L3_GUARD) as *mut u64;

    // Identity-map the whole 2 MiB region as EL1-only 4 KiB pages so the heap and
    // stack pages that share this region keep working.
    let region_base = guard & !(BLOCK_2M - 1);
    for i in 0..ENTRIES {
        *l3.add(i) = page_4k(region_base + i * PAGE_SIZE, false, false);
    }

    // Leave the guard page itself unmapped: an invalid descriptor faults on any
    // access, which is exactly the stack-overflow boundary we want.
    *l3.add(ptable::l3_index(guard)) = 0;

    // Link L3 into the block-1 level-2 table at the guard region's slot.
    *l2.add(ptable::l2_index(guard)) = table_desc(l3 as usize);
}

/// True once translation is on; read back SCTLR_EL1.M.
pub fn is_enabled() -> bool {
    let sctlr: u64;
    unsafe { core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr) };
    sctlr & 1 != 0
}
