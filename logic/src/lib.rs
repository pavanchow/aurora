//! Host-testable core of the Aurora kernel.
//!
//! These modules are the *same source files* the bare-metal kernel compiles, but
//! pulled in here and built for the host so their algorithms can be unit-tested
//! with `cargo test`. They are deliberately free of any hardware access, `asm!`,
//! or MMIO so the exact code that runs on the aarch64 kernel is what the tests
//! exercise. The single source of truth lives under `kernel/src/`.

#[path = "../../kernel/src/crypto.rs"]
pub mod crypto;

#[path = "../../kernel/src/sha2.rs"]
pub mod sha2;

#[path = "../../kernel/src/x25519.rs"]
pub mod x25519;

#[path = "../../kernel/src/ed25519.rs"]
pub mod ed25519;

#[path = "../../kernel/src/x509.rs"]
pub mod x509;

#[path = "../../kernel/src/tls.rs"]
pub mod tls;

#[path = "../../kernel/src/frame_alloc.rs"]
pub mod frame_alloc;

#[path = "../../kernel/src/heap.rs"]
pub mod heap;

#[path = "../../kernel/src/vault.rs"]
pub mod vault;

#[path = "../../kernel/src/ptable.rs"]
pub mod ptable;

// The transport-and-resolver wire logic (UDP, DNS, TCP, HTTP), mounted from the
// exact kernel source so `cargo test` exercises the same encode/parse/checksum
// code the kernel runs. It is pure (no `asm!`, no MMIO), so it builds on the host.
#[path = "../../kernel/src/proto.rs"]
pub mod proto;

#[path = "../../kernel/src/runqueue.rs"]
pub mod runqueue;

// The embedded Kindling bytecode runtime, mounted from the exact kernel source
// so `cargo test` exercises the same interpreter the kernel runs. `alloc` is
// available on the host and the vendored modules use `alloc::` paths.
extern crate alloc;

#[path = "../../kernel/src/kindling/mod.rs"]
pub mod kindling;

/// A host-only tree-walking reference interpreter plus a random program
/// generator, used to differentially test the bytecode VM.
pub mod kref;

use kindling::Outcome;

/// Compile and run a Kindling program on the bytecode VM, returning the produced
/// value and anything it printed.
pub fn run_kindling(src: &str) -> Result<(Outcome, String), String> {
    // Unlimited: the differential test compares pure language semantics against
    // the reference interpreter, so the kernel's compute resource caps (depth,
    // heap bytes) must not perturb it. The caps are exercised by their own unit
    // tests in the VM module.
    let r = kindling::run_source_limited(src, u64::MAX, usize::MAX, usize::MAX)?;
    Ok((r.value, r.output))
}

/// Evaluate a Kindling program with the independent tree-walking reference
/// interpreter, returning the produced value and anything it printed.
pub fn eval_reference(src: &str) -> Result<(Outcome, String), String> {
    let tokens = kindling::lexer::tokenize(src)?;
    let ast = kindling::parser::parse(tokens)?;
    let mut interp = kref::interp::Interp::new();
    let value = interp.run(&ast)?;
    Ok((kref::interp::to_outcome(&value), interp.take_output()))
}
