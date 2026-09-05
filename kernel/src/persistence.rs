//! Persistence guard: the single chokepoint any durable-storage path routes
//! through. Aurora is RAM-only by construction, so there is no block device, no
//! swap, and no persistent log. This guard exists so that "zero durable writes"
//! is an enforced, observable property rather than an implicit one: every code
//! path that would touch durable media must call `guard_durable_write`, which
//! refuses and counts the attempt. `durable_writes()` is therefore always zero,
//! and the boot test asserts it.

use core::sync::atomic::{AtomicU64, Ordering};

static DURABLE_WRITES: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// The one place a would-be durable write is funneled. It never performs the
/// write. It records the refusal and returns an error, so callers cannot leak
/// data to durable media even by mistake.
pub fn guard_durable_write(_what: &str, _bytes: &[u8]) -> Result<(), ()> {
    REFUSED.fetch_add(1, Ordering::Relaxed);
    Err(())
}

/// Durable writes performed this session. Always zero by construction.
pub fn durable_writes() -> u64 {
    DURABLE_WRITES.load(Ordering::Relaxed)
}

/// Number of durable-write attempts the guard refused.
pub fn refused_attempts() -> u64 {
    REFUSED.load(Ordering::Relaxed)
}
