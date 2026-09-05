//! Kernel heap: a first-fit free-list allocator with address-ordered coalescing
//! (pure logic, host-testable).
//!
//! Free memory is tracked by an intrusive singly linked list, kept sorted by
//! address, whose nodes live inside the free regions they describe. Every live
//! allocation is prefixed by a small header recording the exact block extent, so
//! `dealloc` reconstructs and returns precisely what `alloc` consumed. That makes
//! byte accounting exact and lets freed neighbours coalesce back into one region,
//! which keeps fragmentation bounded. The allocator drives a raw address range,
//! so host tests run it over a heap buffer and the kernel runs it over reserved
//! RAM behind a spinlock.

#![allow(dead_code)]

use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::ptr;

#[repr(C)]
struct FreeRegion {
    size: usize,
    next: *mut FreeRegion,
}

#[repr(C)]
struct Header {
    block_start: usize,
    block_end: usize,
}

const NODE_SIZE: usize = size_of::<FreeRegion>();
const NODE_ALIGN: usize = align_of::<FreeRegion>();
const HDR: usize = size_of::<Header>();

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

pub struct Heap {
    head: *mut FreeRegion,
    size: usize,
    used: usize,
}

unsafe impl Send for Heap {}

impl Heap {
    pub const fn empty() -> Self {
        Self { head: ptr::null_mut(), size: 0, used: 0 }
    }

    /// # Safety
    /// `start..start+size` must be valid, writable, otherwise-unused memory that
    /// outlives every allocation handed out by this heap.
    pub unsafe fn init(&mut self, start: usize, size: usize) {
        let aligned = align_up(start, NODE_ALIGN);
        let usable = size.saturating_sub(aligned - start);
        self.size = usable;
        self.used = 0;
        if usable >= NODE_SIZE {
            let node = aligned as *mut FreeRegion;
            (*node).size = usable;
            (*node).next = ptr::null_mut();
            self.head = node;
        } else {
            self.head = ptr::null_mut();
        }
    }

    /// # Safety
    /// Standard `GlobalAlloc::alloc` contract.
    pub unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        let align = layout.align().max(NODE_ALIGN);

        let mut prev: *mut FreeRegion = ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let rs = cur as usize;
            let re = rs + (*cur).size;
            let next = (*cur).next;

            // Reserve room for the header ahead of an aligned payload pointer.
            let payload = align_up(rs + HDR, align);
            let mut block_end = align_up(payload + size, NODE_ALIGN);

            if block_end <= re {
                let mut tail = re - block_end;
                if tail > 0 && tail < NODE_SIZE {
                    // Too small to be its own node: fold it into this block.
                    block_end = re;
                    tail = 0;
                }

                // Unlink this region.
                if prev.is_null() {
                    self.head = next;
                } else {
                    (*prev).next = next;
                }

                // Return the tail remainder to the pool.
                if tail >= NODE_SIZE {
                    let node = block_end as *mut FreeRegion;
                    (*node).size = tail;
                    (*node).next = ptr::null_mut();
                    self.insert_sorted(node);
                }

                let hdr = (payload - HDR) as *mut Header;
                (*hdr).block_start = rs;
                (*hdr).block_end = block_end;
                self.used += block_end - rs;
                return payload as *mut u8;
            }

            prev = cur;
            cur = next;
        }
        ptr::null_mut()
    }

    /// # Safety
    /// `ptr` must have come from `alloc` on this heap and not been freed since.
    pub unsafe fn dealloc(&mut self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let hdr = (ptr as usize - HDR) as *const Header;
        let bs = (*hdr).block_start;
        let be = (*hdr).block_end;
        self.used = self.used.saturating_sub(be - bs);

        let node = bs as *mut FreeRegion;
        (*node).size = be - bs;
        (*node).next = ptr::null_mut();
        self.insert_sorted(node);
    }

    unsafe fn insert_sorted(&mut self, node: *mut FreeRegion) {
        let addr = node as usize;
        if self.head.is_null() || addr < self.head as usize {
            (*node).next = self.head;
            self.head = node;
            self.coalesce(ptr::null_mut(), node);
            return;
        }
        let mut prev = self.head;
        while !(*prev).next.is_null() && ((*prev).next as usize) < addr {
            prev = (*prev).next;
        }
        (*node).next = (*prev).next;
        (*prev).next = node;
        self.coalesce(prev, node);
    }

    unsafe fn coalesce(&mut self, prev: *mut FreeRegion, node: *mut FreeRegion) {
        let next = (*node).next;
        if !next.is_null() && (node as usize) + (*node).size == next as usize {
            (*node).size += (*next).size;
            (*node).next = (*next).next;
        }
        if !prev.is_null() && (prev as usize) + (*prev).size == node as usize {
            (*prev).size += (*node).size;
            (*prev).next = (*node).next;
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.size
    }

    pub fn used_bytes(&self) -> usize {
        self.used
    }

    pub fn free_bytes(&self) -> usize {
        self.size - self.used
    }

    /// Number of distinct free regions. A low count after many frees is the
    /// observable signature that coalescing works.
    pub fn free_region_count(&self) -> usize {
        let mut n = 0;
        let mut cur = self.head;
        while !cur.is_null() {
            n += 1;
            cur = unsafe { (*cur).next };
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc as sys_alloc, dealloc as sys_dealloc, Layout as SysLayout};
    use std::vec::Vec;

    struct Backing {
        ptr: *mut u8,
        layout: SysLayout,
        size: usize,
    }
    impl Backing {
        fn new(size: usize) -> Self {
            let layout = SysLayout::from_size_align(size, 4096).unwrap();
            let ptr = unsafe { sys_alloc(layout) };
            assert!(!ptr.is_null());
            Self { ptr, layout, size }
        }
        fn heap(&self) -> Heap {
            let mut h = Heap::empty();
            unsafe { h.init(self.ptr as usize, self.size) };
            h
        }
        fn contains(&self, p: *mut u8, len: usize) -> bool {
            let a = p as usize;
            a >= self.ptr as usize && a + len <= self.ptr as usize + self.size
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            unsafe { sys_dealloc(self.ptr, self.layout) };
        }
    }

    #[test]
    fn alloc_returns_aligned_in_range_pointers() {
        let b = Backing::new(64 * 1024);
        let mut h = b.heap();
        for align in [8usize, 16, 64, 256, 4096] {
            let l = Layout::from_size_align(100, align).unwrap();
            let p = unsafe { h.alloc(l) };
            assert!(!p.is_null(), "align {align}");
            assert_eq!(p as usize % align, 0, "align {align}");
            assert!(b.contains(p, 100));
        }
    }

    #[test]
    fn distinct_allocations_do_not_overlap() {
        let b = Backing::new(64 * 1024);
        let mut h = b.heap();
        let l = Layout::from_size_align(128, 16).unwrap();
        let mut ranges = Vec::new();
        for _ in 0..64 {
            let p = unsafe { h.alloc(l) } as usize;
            assert_ne!(p, 0);
            ranges.push((p, p + 128));
        }
        ranges.sort();
        for w in ranges.windows(2) {
            assert!(w[0].1 <= w[1].0, "overlap: {:x?} {:x?}", w[0], w[1]);
        }
    }

    #[test]
    fn free_then_alloc_conserves_bytes() {
        let b = Backing::new(64 * 1024);
        let mut h = b.heap();
        let total = h.free_bytes();
        let l = Layout::from_size_align(512, 16).unwrap();
        let p = unsafe { h.alloc(l) };
        assert!(h.used_bytes() >= 512);
        unsafe { h.dealloc(p, l) };
        assert_eq!(h.used_bytes(), 0, "all bytes returned");
        assert_eq!(h.free_bytes(), total, "byte accounting conserved");
    }

    #[test]
    fn coalescing_rejoins_the_arena() {
        let b = Backing::new(64 * 1024);
        let mut h = b.heap();
        let l = Layout::from_size_align(256, 16).unwrap();
        let mut ps = Vec::new();
        for _ in 0..32 {
            let p = unsafe { h.alloc(l) };
            assert!(!p.is_null());
            ps.push(p);
        }
        for i in (0..ps.len()).rev() {
            unsafe { h.dealloc(ps[i], l) };
        }
        assert_eq!(h.used_bytes(), 0);
        assert_eq!(
            h.free_region_count(),
            1,
            "fully freed heap must coalesce back to a single region"
        );
    }

    #[test]
    fn exhaustion_returns_null() {
        let b = Backing::new(8 * 1024);
        let mut h = b.heap();
        let big = Layout::from_size_align(64 * 1024, 16).unwrap();
        assert!(unsafe { h.alloc(big) }.is_null());
    }

    #[test]
    fn stress_random_alloc_free_conserves() {
        let b = Backing::new(256 * 1024);
        let mut h = b.heap();
        let total = h.free_bytes();
        let mut live: Vec<(*mut u8, Layout)> = Vec::new();
        let mut state: u64 = 0x1234_5678;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            if live.len() > 8 && rng() % 2 == 0 {
                let idx = (rng() as usize) % live.len();
                let (p, l) = live.swap_remove(idx);
                unsafe { h.dealloc(p, l) };
            } else {
                let sz = (rng() as usize % 400) + 1;
                let al = 1usize << (rng() as usize % 6); // 1..32
                let l = Layout::from_size_align(sz, al).unwrap();
                let p = unsafe { h.alloc(l) };
                if !p.is_null() {
                    live.push((p, l));
                }
            }
        }
        for (p, l) in live.drain(..) {
            unsafe { h.dealloc(p, l) };
        }
        assert_eq!(h.used_bytes(), 0, "no bytes leaked after full drain");
        assert_eq!(h.free_bytes(), total);
        assert_eq!(h.free_region_count(), 1, "arena coalesced after drain");
    }
}
