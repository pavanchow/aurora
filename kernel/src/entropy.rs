//! Best-effort session entropy.
//!
//! Aurora has no hardware TRNG on the QEMU `virt` machine. This gathers timing
//! jitter from the ARM generic timer counter (CNTPCT_EL0), sampled across small
//! variable-length delays, then diffuses the samples through one ChaCha20 block
//! so every output bit depends on every input bit. On real hardware the counter
//! plus interrupt jitter carries some genuine unpredictability. On deterministic
//! QEMU it does not, so this is documented honestly as BEST-EFFORT: it is not a
//! cryptographically strong RNG and must not be relied on where real entropy is
//! required. It exists to give each session a distinct in-RAM key that never
//! touches durable media and dies on wipe.

use crate::crypto;

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Generate a fresh 32-byte session key. Kept only in RAM by the caller.
pub fn session_key() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for s in seed.iter_mut() {
        let t = cntpct();
        *s = (t ^ (t >> 13) ^ (t >> 29) ^ (t >> 41)) as u8;
        // Variable-length spin so successive samples land at unequal offsets.
        let spins = (t & 0x3f) + 1;
        for _ in 0..spins {
            core::hint::spin_loop();
        }
    }
    // Diffuse: use the raw samples as a key and the live counter as counter and
    // nonce, then take the first 32 bytes of the keystream block.
    let t = cntpct();
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&t.to_le_bytes());
    let mut block = [0u8; 64];
    crypto::chacha20_block(&seed, t as u32, &nonce, &mut block);
    let mut key = [0u8; 32];
    key.copy_from_slice(&block[..32]);
    key
}
