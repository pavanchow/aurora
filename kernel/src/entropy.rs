//! Session entropy, best strong source available.
//!
//! Preference order:
//!  1. ARMv8.5 RNDR/RNDRRS, a real on-chip hardware RNG, detected at runtime via
//!     ID_AA64ISAR0_EL1.RNDR. This is a cryptographic entropy source.
//!  2. (Documented alternative) a virtio-rng device on the QEMU `virt` machine.
//!     Aurora reads hardware RNDR when present, which QEMU's `-cpu max` provides,
//!     so the virtio path is not needed on our machine.
//!  3. Fallback: timing jitter from the generic timer counter (CNTPCT_EL0),
//!     diffused through one ChaCha20 block. On deterministic QEMU this carries
//!     little real unpredictability, so it is honestly labelled BEST-EFFORT and
//!     is only reached when no hardware RNG exists.
//!
//! Whichever source is used, the key stays only in RAM and dies on wipe. The
//! source actually used is recorded so the shell and the amnesia proof can report
//! it.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::crypto;

const SRC_UNKNOWN: u8 = 0;
const SRC_RNDR: u8 = 1;
const SRC_TIMER: u8 = 2;

static LAST_SOURCE: AtomicU8 = AtomicU8::new(SRC_UNKNOWN);

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// True if the CPU implements the ARMv8.5 RNG extension (RNDR/RNDRRS).
fn has_rndr() -> bool {
    let isar0: u64;
    unsafe { core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack)) };
    // RNDR occupies bits [63:60]; any non-zero value means it is implemented.
    (isar0 >> 60) & 0xf != 0
}

/// Read the RNDR hardware RNG. Returns None if it could not return a genuine
/// random value (RNDR sets PSTATE.Z on failure). Encoded as the raw system
/// register S3_3_C2_C4_0 so it assembles without a target-feature flag.
fn rndr64() -> Option<u64> {
    let val: u64;
    let failed: u64;
    unsafe {
        core::arch::asm!(
            "mrs {v}, s3_3_c2_c4_0",
            "cset {f}, eq",
            v = out(reg) val,
            f = out(reg) failed,
            options(nostack),
        );
    }
    if failed != 0 {
        None
    } else {
        Some(val)
    }
}

/// Fill 32 bytes from RNDR, retrying transient failures. Returns false if the
/// hardware RNG never yielded a value within the retry budget.
fn fill_from_rndr(key: &mut [u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        let mut got = None;
        for _ in 0..64 {
            if let Some(v) = rndr64() {
                got = Some(v);
                break;
            }
        }
        let v = match got {
            Some(v) => v,
            None => return false,
        };
        let bytes = v.to_le_bytes();
        let n = core::cmp::min(8, 32 - i);
        key[i..i + n].copy_from_slice(&bytes[..n]);
        i += n;
    }
    true
}

/// Best-effort timer-jitter key (fallback only).
fn timer_key() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for s in seed.iter_mut() {
        let t = cntpct();
        *s = (t ^ (t >> 13) ^ (t >> 29) ^ (t >> 41)) as u8;
        let spins = (t & 0x3f) + 1;
        for _ in 0..spins {
            core::hint::spin_loop();
        }
    }
    let t = cntpct();
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&t.to_le_bytes());
    let mut block = [0u8; 64];
    crypto::chacha20_block(&seed, t as u32, &nonce, &mut block);
    let mut key = [0u8; 32];
    key.copy_from_slice(&block[..32]);
    key
}

/// Generate a fresh 32-byte session key. Kept only in RAM by the caller.
pub fn session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    if has_rndr() && fill_from_rndr(&mut key) {
        LAST_SOURCE.store(SRC_RNDR, Ordering::Relaxed);
        return key;
    }
    LAST_SOURCE.store(SRC_TIMER, Ordering::Relaxed);
    timer_key()
}

/// Human-readable name of the entropy source used for the most recent key.
pub fn source_name() -> &'static str {
    match LAST_SOURCE.load(Ordering::Relaxed) {
        SRC_RNDR => "RNDR (ARMv8.5 hardware RNG)",
        SRC_TIMER => "timer jitter (best-effort)",
        _ => "none yet",
    }
}
