//! Kernel memory init: wires the pure frame allocator and free-list heap to the
//! RAM regions the linker script reserves, and installs the global allocator so
//! `Box`/`Vec`/`String` work.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::addr_of_mut;

use crate::frame_alloc::{FrameAllocator, FRAME_SIZE};
use crate::heap::Heap;
use crate::sync::SpinLock;

extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
    static __frames_start: u8;
    static __frames_end: u8;
    static __vault_start: u8;
    static __vault_end: u8;
    static __stack_bottom: u8;
    static __stack_top: u8;
    static __netbuf_start: u8;
    static __netbuf_end: u8;
}

fn sym(p: *const u8) -> usize {
    p as usize
}

// --- Global heap allocator ---------------------------------------------------

struct LockedHeap(SpinLock<Heap>);

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap(SpinLock::new(Heap::empty()));

// --- Global frame allocator --------------------------------------------------

const POOL_BYTES: usize = 0x0200_0000; // must match linker frame pool size
const POOL_FRAMES: usize = POOL_BYTES / FRAME_SIZE;

static mut FRAME_BITMAP: [u64; FrameAllocator::words_for(POOL_FRAMES)] =
    [0; FrameAllocator::words_for(POOL_FRAMES)];

static FRAMES: SpinLock<Option<FrameAllocator<'static>>> = SpinLock::new(None);

pub fn init() {
    unsafe {
        let hstart = sym(&__heap_start);
        let hend = sym(&__heap_end);
        ALLOCATOR.0.lock().init(hstart, hend - hstart);

        let fstart = sym(&__frames_start);
        let fend = sym(&__frames_end);
        let bitmap: &'static mut [u64] = &mut *addr_of_mut!(FRAME_BITMAP);
        *FRAMES.lock() = Some(FrameAllocator::new(fstart, fend - fstart, bitmap));
    }
}

pub fn heap_total() -> usize {
    ALLOCATOR.0.lock().total_bytes()
}

pub fn heap_used() -> usize {
    ALLOCATOR.0.lock().used_bytes()
}

pub fn heap_free() -> usize {
    ALLOCATOR.0.lock().free_bytes()
}

/// Allocate one physical frame.
pub fn alloc_frame() -> Option<usize> {
    FRAMES.lock().as_mut().and_then(|f| f.alloc())
}

/// Free one physical frame.
pub fn free_frame(addr: usize) {
    if let Some(f) = FRAMES.lock().as_mut() {
        f.free(addr);
    }
}

pub fn frames_total() -> usize {
    FRAMES.lock().as_ref().map(|f| f.total_frames()).unwrap_or(0)
}

pub fn frames_free() -> usize {
    FRAMES.lock().as_ref().map(|f| f.free_frames()).unwrap_or(0)
}

/// Physical frame pool byte range `[start, end)`. This is scratch RAM the frame
/// allocator hands out, so the wipe can scrub and the amnesia scan can sweep the
/// whole region without disturbing live kernel state.
pub fn frame_pool_range() -> (usize, usize) {
    unsafe { (sym(&__frames_start), sym(&__frames_end)) }
}

/// Reserved vault region byte range `[start, end)`.
pub fn vault_region_range() -> (usize, usize) {
    unsafe { (sym(&__vault_start), sym(&__vault_end)) }
}

/// Boot/kernel stack byte range `[bottom, top)`. The stack grows down from the
/// top, so `[bottom, current_sp)` is the free part below the live frames and is
/// safe to scrub, while `[current_sp, top)` holds the live frames in use.
pub fn stack_region_range() -> (usize, usize) {
    unsafe { (sym(&__stack_bottom), sym(&__stack_top)) }
}

/// Network scratch region byte range `[start, end)`. Holds the virtio-net rings
/// and all DNS/TCP/HTTP receive buffers plus the fetched body, so the wipe scrubs
/// them and the amnesia scan can sweep the whole region.
pub fn netbuf_region_range() -> (usize, usize) {
    unsafe { (sym(&__netbuf_start), sym(&__netbuf_end)) }
}

/// The reserved vault region as a mutable static slice. Must be called at most
/// once; the returned slice aliases the whole reserved region.
///
/// # Safety
/// The caller must ensure no other reference to the vault region exists.
pub unsafe fn vault_region_slice() -> &'static mut [u8] {
    let (start, end) = vault_region_range();
    core::slice::from_raw_parts_mut(start as *mut u8, end - start)
}
