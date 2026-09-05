//! Encrypted in-RAM session vault (pure logic, host-testable).
//!
//! The vault stores agent and session secrets encrypted with the from-scratch
//! ChaCha20-Poly1305 AEAD in `crypto`. Records live inside a caller-supplied RAM
//! region as a simple append log, so the whole region can be scrubbed in one
//! sweep on wipe and scanned by the amnesia proof. The 32-byte session key lives
//! inside the vault and is the first thing zeroed on wipe. Nothing here allocates
//! or touches hardware, so the kernel drives it over reserved RAM and host tests
//! drive it over an ordinary buffer.

#![allow(dead_code)]

use crate::crypto::{self, KEY_LEN, NONCE_LEN, TAG_LEN};

pub const MAX_KEY: usize = 32;
pub const MAX_VAL: usize = 192;

/// Overwrite a buffer with zeros so a compiler cannot elide the scrub. Used to
/// wipe transient plaintext staging buffers on the stack the instant a vault
/// operation finishes, so decrypted secrets never outlive the call on the stack.
#[inline(never)]
pub(crate) fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// Record layout in the region: key_len(1) val_len(1) nonce(12) tag(16) key ct.
const HDR: usize = 1 + 1 + NONCE_LEN + TAG_LEN;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    KeyTooLong,
    ValTooLong,
    OutOfSpace,
}

pub struct Vault<'a> {
    region: &'a mut [u8],
    key: [u8; KEY_LEN],
    cursor: usize,
    count: u64,
}

impl<'a> Vault<'a> {
    /// Build a vault over `region` with session key `key`. The region is cleared.
    pub fn new(region: &'a mut [u8], key: [u8; KEY_LEN]) -> Self {
        for b in region.iter_mut() {
            *b = 0;
        }
        Self { region, key, cursor: 0, count: 0 }
    }

    fn nonce_for(counter: u64) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[..8].copy_from_slice(&counter.to_le_bytes());
        n
    }

    /// Encrypt `val` under `key_str` and append it. Writes the ciphertext bytes
    /// into `ct_out` (for display) and returns the ciphertext length.
    pub fn put(&mut self, key_str: &str, val: &[u8], ct_out: &mut [u8]) -> Result<usize, VaultError> {
        let kb = key_str.as_bytes();
        if kb.len() > MAX_KEY {
            return Err(VaultError::KeyTooLong);
        }
        if val.len() > MAX_VAL {
            return Err(VaultError::ValTooLong);
        }
        let need = HDR + kb.len() + val.len();
        if self.cursor + need > self.region.len() {
            return Err(VaultError::OutOfSpace);
        }

        let mut buf = [0u8; MAX_VAL];
        buf[..val.len()].copy_from_slice(val);
        let ct = &mut buf[..val.len()];
        let nonce = Self::nonce_for(self.count);
        let tag = crypto::aead_seal(&self.key, &nonce, kb, ct);

        let base = self.cursor;
        self.region[base] = kb.len() as u8;
        self.region[base + 1] = val.len() as u8;
        self.region[base + 2..base + 2 + NONCE_LEN].copy_from_slice(&nonce);
        self.region[base + 2 + NONCE_LEN..base + HDR].copy_from_slice(&tag);
        self.region[base + HDR..base + HDR + kb.len()].copy_from_slice(kb);
        self.region[base + HDR + kb.len()..base + need].copy_from_slice(ct);

        if ct_out.len() >= ct.len() {
            ct_out[..ct.len()].copy_from_slice(ct);
        }
        let n = ct.len();
        // Scrub the staging buffer: it held the plaintext before the in-place
        // seal, so nothing plaintext (or ciphertext) lingers on the stack.
        zeroize(&mut buf);
        self.cursor += need;
        self.count += 1;
        Ok(n)
    }

    /// Decrypt the latest value stored under `key_str` into `out`. Returns the
    /// plaintext length, or None if absent or authentication fails.
    pub fn get(&self, key_str: &str, out: &mut [u8]) -> Option<usize> {
        let kb = key_str.as_bytes();
        let mut off = 0;
        let mut found: Option<usize> = None;
        // Scan forward, keep the last matching record (put overwrites logically).
        while off + HDR <= self.cursor {
            let kl = self.region[off] as usize;
            let vl = self.region[off + 1] as usize;
            let rec = HDR + kl + vl;
            if off + rec > self.cursor {
                break;
            }
            if kl == kb.len() && &self.region[off + HDR..off + HDR + kl] == kb {
                found = Some(off);
            }
            off += rec;
        }
        let off = found?;
        let kl = self.region[off] as usize;
        let vl = self.region[off + 1] as usize;
        if out.len() < vl {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&self.region[off + 2..off + 2 + NONCE_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&self.region[off + 2 + NONCE_LEN..off + HDR]);
        let ct_start = off + HDR + kl;
        let mut buf = [0u8; MAX_VAL];
        buf[..vl].copy_from_slice(&self.region[ct_start..ct_start + vl]);
        if crypto::aead_open(&self.key, &nonce, kb, &mut buf[..vl], &tag) {
            out[..vl].copy_from_slice(&buf[..vl]);
            // Scrub the decrypted plaintext from the stack staging buffer.
            zeroize(&mut buf);
            Some(vl)
        } else {
            zeroize(&mut buf);
            None
        }
    }

    /// Number of records stored.
    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Bytes of the region currently in use.
    pub fn used(&self) -> usize {
        self.cursor
    }

    /// Invoke `f(key_bytes)` for each stored record's key (for `vault list`).
    pub fn for_each_key(&self, mut f: impl FnMut(&[u8])) {
        let mut off = 0;
        while off + HDR <= self.cursor {
            let kl = self.region[off] as usize;
            let vl = self.region[off + 1] as usize;
            let rec = HDR + kl + vl;
            if off + rec > self.cursor {
                break;
            }
            f(&self.region[off + HDR..off + HDR + kl]);
            off += rec;
        }
    }

    /// Zero the session key only. This is the very first action of a wipe: the
    /// key is the highest-value secret, so it dies before anything else.
    pub fn zero_key(&mut self) -> usize {
        for b in self.key.iter_mut() {
            *b = 0;
        }
        self.key.len()
    }

    /// Scrub the vault: zero the session key FIRST, then the whole region.
    /// Returns the number of bytes overwritten (key + region).
    pub fn wipe(&mut self) -> usize {
        for b in self.key.iter_mut() {
            *b = 0;
        }
        for b in self.region.iter_mut() {
            *b = 0;
        }
        let n = self.key.len() + self.region.len();
        self.cursor = 0;
        self.count = 0;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn key() -> [u8; KEY_LEN] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1))
    }

    #[test]
    fn put_get_round_trip() {
        let mut region = vec![0u8; 4096];
        let mut v = Vault::new(&mut region, key());
        let mut ct = [0u8; MAX_VAL];
        v.put("api-token", b"hunter2-secret", &mut ct).unwrap();
        let mut out = [0u8; MAX_VAL];
        let n = v.get("api-token", &mut out).unwrap();
        assert_eq!(&out[..n], b"hunter2-secret");
    }

    #[test]
    fn stored_bytes_are_ciphertext_not_plaintext() {
        let mut region = vec![0u8; 4096];
        let plaintext = b"the-plaintext-secret-value";
        {
            let mut v = Vault::new(&mut region, key());
            let mut ct = [0u8; MAX_VAL];
            v.put("k", plaintext, &mut ct).unwrap();
        }
        // The plaintext must not appear anywhere in the backing region.
        let found = region.windows(plaintext.len()).any(|w| w == plaintext);
        assert!(!found, "plaintext leaked into vault region");
    }

    #[test]
    fn missing_key_returns_none() {
        let mut region = vec![0u8; 4096];
        let v = Vault::new(&mut region, key());
        let mut out = [0u8; MAX_VAL];
        assert_eq!(v.get("nope", &mut out), None);
    }

    #[test]
    fn multiple_records_and_latest_wins() {
        let mut region = vec![0u8; 4096];
        let mut v = Vault::new(&mut region, key());
        let mut ct = [0u8; MAX_VAL];
        v.put("a", b"first", &mut ct).unwrap();
        v.put("b", b"other", &mut ct).unwrap();
        v.put("a", b"second", &mut ct).unwrap();
        let mut out = [0u8; MAX_VAL];
        let n = v.get("a", &mut out).unwrap();
        assert_eq!(&out[..n], b"second");
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn wipe_zeros_key_and_region_and_forgets() {
        let mut region = vec![0u8; 1024];
        let secret = b"do-not-persist-me";
        let mut v = Vault::new(&mut region, key());
        let mut ct = [0u8; MAX_VAL];
        v.put("s", secret, &mut ct).unwrap();
        let wiped = v.wipe();
        assert_eq!(wiped, KEY_LEN + 1024);
        // After wipe the key is zero and the region is all zero.
        assert!(v.get("s", &mut [0u8; MAX_VAL]).is_none());
        drop(v);
        assert!(region.iter().all(|&b| b == 0), "region not fully scrubbed");
        // The secret plaintext is gone from the region.
        assert!(!region.windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn out_of_space_is_reported() {
        let mut region = vec![0u8; HDR + 2 + 4]; // room for exactly one tiny record
        let mut v = Vault::new(&mut region, key());
        let mut ct = [0u8; MAX_VAL];
        v.put("ab", b"data", &mut ct).unwrap();
        assert_eq!(v.put("cd", b"more", &mut ct), Err(VaultError::OutOfSpace));
    }
}
