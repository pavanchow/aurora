//! Physical frame allocator (pure logic, host-testable).
//!
//! A bitmap allocator over a contiguous physical region carved into fixed-size
//! frames. The bitmap storage is supplied by the caller so this type is free of
//! any global state and can be unit-tested on the host with an ordinary slice.

#![allow(dead_code)]

pub const FRAME_SIZE: usize = 4096;

pub struct FrameAllocator<'a> {
    base: usize,
    frames: usize,
    bitmap: &'a mut [u64],
    allocated: usize,
    cursor: usize,
}

impl<'a> FrameAllocator<'a> {
    /// Number of u64 words needed to track `frames` frames.
    pub const fn words_for(frames: usize) -> usize {
        frames.div_ceil(64)
    }

    /// Build an allocator over `[base, base + size)`. `bitmap` must hold at least
    /// `words_for(size / FRAME_SIZE)` words; it is cleared to "all free".
    pub fn new(base: usize, size: usize, bitmap: &'a mut [u64]) -> Self {
        let frames = size / FRAME_SIZE;
        assert!(bitmap.len() >= Self::words_for(frames), "bitmap too small");
        for w in bitmap.iter_mut() {
            *w = 0;
        }
        Self { base, frames, bitmap, allocated: 0, cursor: 0 }
    }

    #[inline]
    fn is_set(&self, i: usize) -> bool {
        (self.bitmap[i / 64] >> (i % 64)) & 1 == 1
    }

    #[inline]
    fn set(&mut self, i: usize) {
        self.bitmap[i / 64] |= 1 << (i % 64);
    }

    #[inline]
    fn clear(&mut self, i: usize) {
        self.bitmap[i / 64] &= !(1 << (i % 64));
    }

    /// Allocate one frame, returning its physical base address.
    pub fn alloc(&mut self) -> Option<usize> {
        if self.allocated == self.frames {
            return None;
        }
        for step in 0..self.frames {
            let i = (self.cursor + step) % self.frames;
            if !self.is_set(i) {
                self.set(i);
                self.allocated += 1;
                self.cursor = (i + 1) % self.frames;
                return Some(self.base + i * FRAME_SIZE);
            }
        }
        None
    }

    /// Free a previously allocated frame. Panics on an out-of-range or unaligned
    /// address, or a double free (all real bugs we want to catch loudly).
    pub fn free(&mut self, addr: usize) {
        assert!(addr >= self.base, "frame below pool");
        let off = addr - self.base;
        assert!(off.is_multiple_of(FRAME_SIZE), "unaligned frame free");
        let i = off / FRAME_SIZE;
        assert!(i < self.frames, "frame above pool");
        assert!(self.is_set(i), "double free");
        self.clear(i);
        self.allocated -= 1;
        self.cursor = i;
    }

    pub fn total_frames(&self) -> usize {
        self.frames
    }

    pub fn free_frames(&self) -> usize {
        self.frames - self.allocated
    }

    pub fn used_frames(&self) -> usize {
        self.allocated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::vec::Vec;

    fn make(frames: usize) -> Vec<u64> {
        vec![0u64; FrameAllocator::words_for(frames)]
    }

    #[test]
    fn alloc_is_frame_aligned_and_in_range() {
        let mut bm = make(16);
        let mut fa = FrameAllocator::new(0x4000_0000, 16 * FRAME_SIZE, &mut bm);
        let a = fa.alloc().unwrap();
        assert_eq!(a % FRAME_SIZE, 0);
        assert!((0x4000_0000..0x4000_0000 + 16 * FRAME_SIZE).contains(&a));
    }

    #[test]
    fn exhaustion_returns_none_then_recovers() {
        let mut bm = make(4);
        let mut fa = FrameAllocator::new(0, 4 * FRAME_SIZE, &mut bm);
        let mut got = Vec::new();
        for _ in 0..4 {
            got.push(fa.alloc().unwrap());
        }
        assert_eq!(fa.free_frames(), 0);
        assert!(fa.alloc().is_none());
        fa.free(got[1]);
        assert_eq!(fa.free_frames(), 1);
        let re = fa.alloc().unwrap();
        assert_eq!(re, got[1]);
        assert!(fa.alloc().is_none());
    }

    #[test]
    fn no_two_live_allocations_alias() {
        let mut bm = make(64);
        let mut fa = FrameAllocator::new(0x8000_0000, 64 * FRAME_SIZE, &mut bm);
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            let f = fa.alloc().unwrap();
            assert!(seen.insert(f), "frame handed out twice: {f:#x}");
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_panics() {
        let mut bm = make(8);
        let mut fa = FrameAllocator::new(0, 8 * FRAME_SIZE, &mut bm);
        let a = fa.alloc().unwrap();
        fa.free(a);
        fa.free(a);
    }

    #[test]
    fn accounting_balances() {
        let mut bm = make(32);
        let mut fa = FrameAllocator::new(0, 32 * FRAME_SIZE, &mut bm);
        assert_eq!(fa.total_frames(), 32);
        let a = fa.alloc().unwrap();
        let b = fa.alloc().unwrap();
        assert_eq!(fa.used_frames(), 2);
        fa.free(a);
        fa.free(b);
        assert_eq!(fa.used_frames(), 0);
        assert_eq!(fa.free_frames(), 32);
    }
}
