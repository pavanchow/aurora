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
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

// Output-address mask for a level-1 1 GiB block: PA[47:30].
const OA_1G_MASK: u64 = 0x0000_FFFF_C000_0000;

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
    fn tcr_and_mair_have_expected_fields() {
        let tcr = tcr_value();
        assert_eq!(tcr & 0x3f, 25, "T0SZ = 25 -> 39-bit VA");
        assert_ne!(tcr & (1 << 23), 0, "TTBR1 walks disabled (EPD1)");
        assert_eq!((tcr >> 14) & 0b11, 0b00, "4 KiB granule (TG0)");
        assert_eq!(mair_value(), 0x00FF);
    }
}
