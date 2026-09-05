//! AArch64 translation-table math and descriptor construction (pure logic,
//! host-testable).
//!
//! Aurora uses a 4 KiB granule with a 39-bit VA (T0SZ = 25), so translation
//! starts at level 1 where each entry maps a 1 GiB block. These helpers compute
//! the per-level table indices for a virtual address and build the block/table
//! descriptors, isolated from any register writes so they can be unit-tested on
//! the host.

#![allow(dead_code)]

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT; // 4 KiB
pub const ENTRIES: usize = 512; // per 4 KiB table
pub const BLOCK_1G: usize = 1 << 30;
pub const BLOCK_2M: usize = 1 << 21;

// Memory attribute indices into MAIR_EL1.
pub const ATTR_NORMAL: u64 = 0; // MAIR attr0 = 0xFF (normal write-back)
pub const ATTR_DEVICE: u64 = 1; // MAIR attr1 = 0x00 (device nGnRnE)

// Descriptor type/low bits.
const VALID: u64 = 1 << 0;
const BLOCK: u64 = 0 << 1; // block entry at L1/L2
const TABLE: u64 = 1 << 1; // table entry, or page at L3
const AF: u64 = 1 << 10; // access flag
const SH_INNER: u64 = 0b11 << 8; // inner shareable
const SH_NONE: u64 = 0b00 << 8;
const AP_RW_EL1: u64 = 0b00 << 6; // read/write at EL1, no EL0
const AP_RW_ALL: u64 = 0b01 << 6; // read/write at EL1 and EL0
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

// Output-address mask for a level-1 1 GiB block: PA[47:30].
const OA_1G_MASK: u64 = 0x0000_FFFF_C000_0000;
// Output-address mask for a level-2 2 MiB block: PA[47:21].
const OA_2M_MASK: u64 = 0x0000_FFFF_FFE0_0000;
// Next-level table / 4 KiB page output address: PA[47:12].
const ADDR_4K_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// Level-1 table index (bits [38:30]).
#[inline]
pub const fn l1_index(va: usize) -> usize {
    (va >> 30) & (ENTRIES - 1)
}

/// Level-2 table index (bits [29:21]).
#[inline]
pub const fn l2_index(va: usize) -> usize {
    (va >> 21) & (ENTRIES - 1)
}

/// Level-3 table index (bits [20:12]).
#[inline]
pub const fn l3_index(va: usize) -> usize {
    (va >> 12) & (ENTRIES - 1)
}

/// Build a level-1 1 GiB block descriptor mapping VA->`pa`.
/// `device` selects device vs normal memory attributes and execute-never bits.
pub const fn block_1g(pa: usize, device: bool) -> u64 {
    let mut d = ((pa as u64) & OA_1G_MASK) | AF | AP_RW_EL1 | BLOCK | VALID;
    if device {
        d |= SH_NONE | (ATTR_DEVICE << 2) | PXN | UXN;
    } else {
        d |= SH_INNER | (ATTR_NORMAL << 2);
    }
    d
}

/// Build a level-2 2 MiB block descriptor mapping VA->`pa` as normal cacheable
/// RAM. `el0` grants EL0 read/write (else EL1-only). Kernel-executable at EL1
/// (PXN clear) but never at EL0 (UXN set): EL0 code runs from 4 KiB pages.
pub const fn block_2m(pa: usize, el0: bool) -> u64 {
    let mut d = ((pa as u64) & OA_2M_MASK) | AF | BLOCK | VALID | SH_INNER | (ATTR_NORMAL << 2);
    d |= if el0 { AP_RW_ALL } else { AP_RW_EL1 };
    d |= UXN;
    d
}

/// Build a table descriptor pointing at the next-level table at `pa`.
pub const fn table_desc(pa: usize) -> u64 {
    ((pa as u64) & ADDR_4K_MASK) | TABLE | VALID
}

/// Build a level-3 4 KiB page descriptor mapping VA->`pa` as normal cacheable
/// RAM. `el0` grants EL0 read/write. `exec` (only meaningful with `el0`) makes
/// the page EL0-executable (UXN clear) while keeping it non-executable at EL1
/// (PXN set); a non-exec page is execute-never at both levels.
pub const fn page_4k(pa: usize, el0: bool, exec: bool) -> u64 {
    // At level 3 a page descriptor's low bits are 0b11 (TABLE | VALID).
    let mut d = ((pa as u64) & ADDR_4K_MASK) | AF | SH_INNER | (ATTR_NORMAL << 2) | TABLE | VALID;
    d |= if el0 { AP_RW_ALL } else { AP_RW_EL1 };
    if el0 && exec {
        d |= PXN; // EL0 may execute (UXN clear); EL1 may not (PXN set).
    } else {
        d |= UXN | PXN; // no execution at either level.
    }
    d
}

/// MAIR_EL1 value pairing attr0 = normal write-back, attr1 = device nGnRnE.
pub const fn mair_value() -> u64 {
    0x00FF
}

/// TCR_EL1 for a 4 KiB granule, 39-bit VA (T0SZ = 25), TTBR1 disabled,
/// inner-shareable write-back walks, 40-bit intermediate physical size.
pub const fn tcr_value() -> u64 {
    let t0sz: u64 = 25;
    let irgn0: u64 = 0b01 << 8;
    let orgn0: u64 = 0b01 << 10;
    let sh0: u64 = 0b11 << 12;
    let tg0: u64 = 0b00 << 14;
    let epd1: u64 = 1 << 23;
    let ips: u64 = 0b010 << 32;
    t0sz | irgn0 | orgn0 | sh0 | tg0 | epd1 | ips
}

/// Extract the 1 GiB output address from a level-1 block descriptor.
pub const fn block_1g_output(desc: u64) -> usize {
    (desc & OA_1G_MASK) as usize
}

#[inline]
pub const fn is_valid(desc: u64) -> bool {
    desc & VALID != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_decode_known_addresses() {
        // 0x4008_0000 is the kernel load address; it lives in the 1 GiB block 1.
        assert_eq!(l1_index(0x4008_0000), 1);
        // Device block 0 covers the UART and GIC below 1 GiB.
        assert_eq!(l1_index(0x0900_0000), 0);
        assert_eq!(l1_index(0x0800_0000), 0);
        // Boundaries.
        assert_eq!(l1_index(0x0000_0000), 0);
        assert_eq!(l1_index(0x4000_0000), 1);
        assert_eq!(l1_index(0x8000_0000), 2);
        assert_eq!(l1_index(0xC000_0000), 3);
    }

    #[test]
    fn sub_gigabyte_indices() {
        let va = 0x4012_3000;
        assert_eq!(l2_index(va), (va >> 21) & 511);
        assert_eq!(l3_index(va), (va >> 12) & 511);
        // All indices stay inside a table.
        assert!(l1_index(va) < ENTRIES);
        assert!(l2_index(va) < ENTRIES);
        assert!(l3_index(va) < ENTRIES);
    }

    #[test]
    fn block_descriptor_is_identity_and_valid() {
        let pa = 0x4000_0000usize;
        let d = block_1g(pa, false);
        assert!(is_valid(d));
        assert_eq!(block_1g_output(d), pa, "block maps its own PA (identity)");
        // Normal memory: access flag set, attr index 0, inner shareable.
        assert_ne!(d & AF, 0);
        assert_eq!((d >> 2) & 0b111, ATTR_NORMAL);
        assert_eq!((d >> 8) & 0b11, 0b11);
        // Low bits mark a valid block (0b01).
        assert_eq!(d & 0b11, 0b01);
    }

    #[test]
    fn device_block_is_execute_never_and_device_attr() {
        let d = block_1g(0, true);
        assert_eq!((d >> 2) & 0b111, ATTR_DEVICE);
        assert_ne!(d & PXN, 0, "device memory must be PXN");
        assert_ne!(d & UXN, 0, "device memory must be UXN");
        assert_eq!((d >> 8) & 0b11, 0b00, "device is non-shareable");
    }

    #[test]
    fn el0_user_pages_have_expected_permissions() {
        // A 2 MiB kernel block is EL1-only (AP=00) and EL0-non-executable (UXN).
        let k = block_2m(0x4020_0000, false);
        assert!(is_valid(k));
        assert_eq!((k >> 6) & 0b11, 0b00, "kernel block is EL1-only");
        assert_ne!(k & UXN, 0, "kernel block is EL0 non-executable");

        // A user code page is EL0 read/write (AP=01) and EL0-executable (UXN
        // clear) but kernel-non-executable (PXN set).
        let code = page_4k(0x4260_0000, true, true);
        assert_eq!((code >> 6) & 0b11, 0b01, "user code page is EL0-accessible");
        assert_eq!(code & UXN, 0, "user code page is EL0-executable");
        assert_ne!(code & PXN, 0, "user code page is kernel-non-executable");
        assert_eq!(code & 0b11, 0b11, "level-3 page descriptor low bits");

        // A user data/stack page is EL0 read/write but execute-never everywhere.
        let stack = page_4k(0x4260_1000, true, false);
        assert_eq!((stack >> 6) & 0b11, 0b01, "user stack is EL0-accessible");
        assert_ne!(stack & UXN, 0, "user stack is EL0 non-executable");
        assert_ne!(stack & PXN, 0, "user stack is kernel-non-executable");

        // A table descriptor carries the aligned next-level address and is valid.
        let t = table_desc(0x4270_0000);
        assert_eq!(t & 0b11, 0b11, "table descriptor low bits");
        assert_eq!((t & ADDR_4K_MASK) as usize, 0x4270_0000);
    }

    #[test]
    fn tcr_and_mair_have_expected_fields() {
        let tcr = tcr_value();
        assert_eq!(tcr & 0x3f, 25, "T0SZ = 25 -> 39-bit VA");
        assert_ne!(tcr & (1 << 23), 0, "TTBR1 walks disabled (EPD1)");
        assert_eq!((tcr >> 14) & 0b11, 0b00, "4 KiB granule (TG0)");
        assert_eq!(mair_value(), 0x00FF);
    }
}
