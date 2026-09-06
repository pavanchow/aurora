//! User-pointer validation for EL0 syscall arguments (a small `uaccess` layer).
//!
//! A syscall handler that forms a slice from an EL0-supplied `(ptr, len)` must
//! first prove the whole byte range lies inside the calling task's mapped user
//! region and that `len` is sane. Otherwise a user task could hand the kernel a
//! pointer into kernel RAM (the vault, the session key) and have the kernel read
//! or write it on the task's behalf, defeating the EL0/EL1 boundary the page
//! tables enforce against direct EL0 access.
//!
//! The range test is a pure function of the pointer, the length, the region
//! bounds, and a maximum length, so it is unit-tested on the host through the
//! `aurora-logic` crate. The kernel wires in the live region bounds in `syscall`.

/// True when the byte range `[ptr, ptr + len)` lies wholly within the region
/// `[region_start, region_end)` and `len` does not exceed `max_len`. Rejects any
/// range whose end computation would overflow the address space.
pub fn range_in_region(
    ptr: usize,
    len: usize,
    region_start: usize,
    region_end: usize,
    max_len: usize,
) -> bool {
    if len > max_len {
        return false;
    }
    match ptr.checked_add(len) {
        Some(end) => ptr >= region_start && end <= region_end,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: usize = 0x4020_0000;
    const END: usize = 0x4020_2000; // two 4 KiB pages
    const MAX: usize = 64 * 1024;

    #[test]
    fn accepts_a_range_fully_inside() {
        assert!(range_in_region(START, 16, START, END, MAX));
        assert!(range_in_region(START + 100, 200, START, END, MAX));
        assert!(range_in_region(END - 1, 1, START, END, MAX)); // last byte
        assert!(range_in_region(START, 0, START, END, MAX)); // empty range
        assert!(range_in_region(START, END - START, START, END, MAX)); // exact fit
    }

    #[test]
    fn rejects_a_pointer_below_the_region() {
        assert!(!range_in_region(START - 1, 16, START, END, MAX));
        assert!(!range_in_region(0, 8, START, END, MAX));
    }

    #[test]
    fn rejects_a_range_past_the_region_end() {
        assert!(!range_in_region(END - 4, 8, START, END, MAX)); // straddles the end
        assert!(!range_in_region(END, 1, START, END, MAX));
        assert!(!range_in_region(END + 0x1000, 16, START, END, MAX)); // vault-like ptr
    }

    #[test]
    fn rejects_an_absurd_length() {
        assert!(!range_in_region(START, MAX + 1, START, END, MAX));
        assert!(!range_in_region(START, 0xffff_ffff, START, END, MAX));
        assert!(!range_in_region(START, usize::MAX, START, END, MAX));
    }

    #[test]
    fn rejects_an_overflowing_range() {
        // len within max but ptr + len wraps the address space.
        assert!(!range_in_region(usize::MAX - 4, 8, 0, usize::MAX, usize::MAX));
    }
}
