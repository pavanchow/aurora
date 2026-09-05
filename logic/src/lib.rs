//! Host-testable core of the Aurora kernel.
//!
//! These modules are the *same source files* the bare-metal kernel compiles, but
//! pulled in here and built for the host so their algorithms can be unit-tested
//! with `cargo test`. They are deliberately free of any hardware access, `asm!`,
//! or MMIO so the exact code that runs on the aarch64 kernel is what the tests
//! exercise. The single source of truth lives under `kernel/src/`.

#[path = "../../kernel/src/frame_alloc.rs"]
pub mod frame_alloc;

#[path = "../../kernel/src/heap.rs"]
pub mod heap;

#[path = "../../kernel/src/ptable.rs"]
pub mod ptable;

#[path = "../../kernel/src/runqueue.rs"]
pub mod runqueue;
