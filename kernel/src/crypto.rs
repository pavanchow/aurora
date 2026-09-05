//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD, implemented from scratch
//! with zero external crates (pure logic, host-testable).
//!
//! This is the cryptographic core of Aurora's in-RAM session vault. It follows
//! RFC 8439 and is exercised on the host with the RFC's own known-answer test
//! vectors, so the exact code that runs in the bare-metal kernel is what the
//! tests validate. Nothing here touches hardware, `asm!`, or allocation: every
//! routine works on caller-supplied slices, which keeps it usable both under
//! `no_std` in the kernel and under `std` in the `logic` crate's test harness.

#![allow(dead_code)]

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[inline]
fn le32(b: &[u8], i: usize) -> u32 {
    (b[i] as u32) | ((b[i + 1] as u32) << 8) | ((b[i + 2] as u32) << 16) | ((b[i + 3] as u32) << 24)
}

// --- ChaCha20 (RFC 8439 section 2.3) -----------------------------------------

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// Produce one 64-byte ChaCha20 keystream block into `out`.
pub fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], out: &mut [u8; 64]) {
    let mut state: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        le32(key, 0),
        le32(key, 4),
        le32(key, 8),
        le32(key, 12),
        le32(key, 16),
        le32(key, 20),
        le32(key, 24),
        le32(key, 28),
        counter,
        le32(nonce, 0),
        le32(nonce, 4),
        le32(nonce, 8),
    ];
    let mut working = state;
    for _ in 0..10 {
        // Column rounds.
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(working[i]);
    }
    for i in 0..16 {
        let w = state[i].to_le_bytes();
        out[i * 4] = w[0];
        out[i * 4 + 1] = w[1];
        out[i * 4 + 2] = w[2];
        out[i * 4 + 3] = w[3];
    }
}

/// Encrypt or decrypt `buf` in place with ChaCha20, starting at block counter
/// `counter`. Encryption and decryption are the same operation.
pub fn chacha20_xor(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    let mut block = [0u8; 64];
    let mut ctr = counter;
    let mut off = 0;
    while off < buf.len() {
        chacha20_block(key, ctr, nonce, &mut block);
        let n = core::cmp::min(64, buf.len() - off);
        for i in 0..n {
            buf[off + i] ^= block[i];
        }
        off += n;
        ctr = ctr.wrapping_add(1);
    }
}

// --- Poly1305 (RFC 8439 section 2.5) -----------------------------------------
//
// A 32-bit limb implementation (five 26-bit limbs) after the well-known
// poly1305-donna reference. Streaming `update`/`finish` lets the AEAD feed the
// padded associated data, ciphertext and length block as separate chunks.

pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    leftover: usize,
    buffer: [u8; 16],
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = le32(key, 0);
        let t1 = le32(key, 4);
        let t2 = le32(key, 8);
        let t3 = le32(key, 12);
        let r = [
            t0 & 0x03ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff,
            (t3 >> 8) & 0x000f_ffff,
        ];
        let pad = [le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28)];
        Self { r, h: [0; 5], pad, leftover: 0, buffer: [0; 16] }
    }

    fn block(&mut self, m: &[u8], hibit_final: bool) {
        let hibit: u32 = if hibit_final { 0 } else { 1 << 24 };
        let (r0, r1, r2, r3, r4) =
            (self.r[0], self.r[1], self.r[2], self.r[3], self.r[4]);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        h0 = h0.wrapping_add(le32(m, 0) & 0x03ff_ffff);
        h1 = h1.wrapping_add((le32(m, 3) >> 2) & 0x03ff_ffff);
        h2 = h2.wrapping_add((le32(m, 6) >> 4) & 0x03ff_ffff);
        h3 = h3.wrapping_add((le32(m, 9) >> 6) & 0x03ff_ffff);
        h4 = h4.wrapping_add((le32(m, 12) >> 8) | hibit);

        let d0 = (h0 as u64) * (r0 as u64)
            + (h1 as u64) * (s4 as u64)
            + (h2 as u64) * (s3 as u64)
            + (h3 as u64) * (s2 as u64)
            + (h4 as u64) * (s1 as u64);
        let mut d1 = (h0 as u64) * (r1 as u64)
            + (h1 as u64) * (r0 as u64)
            + (h2 as u64) * (s4 as u64)
            + (h3 as u64) * (s3 as u64)
            + (h4 as u64) * (s2 as u64);
        let mut d2 = (h0 as u64) * (r2 as u64)
            + (h1 as u64) * (r1 as u64)
            + (h2 as u64) * (r0 as u64)
            + (h3 as u64) * (s4 as u64)
            + (h4 as u64) * (s3 as u64);
        let mut d3 = (h0 as u64) * (r3 as u64)
            + (h1 as u64) * (r2 as u64)
            + (h2 as u64) * (r1 as u64)
            + (h3 as u64) * (r0 as u64)
            + (h4 as u64) * (s4 as u64);
        let mut d4 = (h0 as u64) * (r4 as u64)
            + (h1 as u64) * (r3 as u64)
            + (h2 as u64) * (r2 as u64)
            + (h3 as u64) * (r1 as u64)
            + (h4 as u64) * (r0 as u64);

        let mut c: u64;
        c = d0 >> 26;
        h0 = (d0 as u32) & 0x03ff_ffff;
        d1 += c;
        c = d1 >> 26;
        h1 = (d1 as u32) & 0x03ff_ffff;
        d2 += c;
        c = d2 >> 26;
        h2 = (d2 as u32) & 0x03ff_ffff;
        d3 += c;
        c = d3 >> 26;
        h3 = (d3 as u32) & 0x03ff_ffff;
        d4 += c;
        c = d4 >> 26;
        h4 = (d4 as u32) & 0x03ff_ffff;
        h0 = h0.wrapping_add((c as u32).wrapping_mul(5));
        c = (h0 >> 26) as u64;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c as u32);

        self.h = [h0, h1, h2, h3, h4];
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.leftover > 0 {
            let want = core::cmp::min(16 - self.leftover, data.len());
            self.buffer[self.leftover..self.leftover + want].copy_from_slice(&data[..want]);
            self.leftover += want;
            data = &data[want..];
            if self.leftover < 16 {
                return;
            }
            let buf = self.buffer;
            self.block(&buf, false);
            self.leftover = 0;
        }
        while data.len() >= 16 {
            self.block(&data[..16], false);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.leftover = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.leftover > 0 {
            let n = self.leftover;
            self.buffer[n] = 1;
            for b in self.buffer.iter_mut().skip(n + 1) {
                *b = 0;
            }
            let buf = self.buffer;
            self.block(&buf, true);
        }

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 = h2.wrapping_add(c);
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 = h3.wrapping_add(c);
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 = h4.wrapping_add(c);
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c);

        // Compute h + -p.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select g if h >= p (i.e. g4 did not borrow), else keep h.
        let mut mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4m = g4 & mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4m;

        // Collapse the 26-bit limbs into 32-bit words. These are u32, so the
        // high bits shifted past bit 31 are dropped, which is the intended
        // mod-2^32 behaviour of the reference implementation.
        let hh0 = h0 | (h1 << 26);
        let hh1 = (h1 >> 6) | (h2 << 20);
        let hh2 = (h2 >> 12) | (h3 << 14);
        let hh3 = (h3 >> 18) | (h4 << 8);

        // mac = (h + pad) mod 2^128.
        let mut f = (hh0 as u64) + (self.pad[0] as u64);
        let m0 = f as u32;
        f = (hh1 as u64) + (self.pad[1] as u64) + (f >> 32);
        let m1 = f as u32;
        f = (hh2 as u64) + (self.pad[2] as u64) + (f >> 32);
        let m2 = f as u32;
        f = (hh3 as u64) + (self.pad[3] as u64) + (f >> 32);
        let m3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&m0.to_le_bytes());
        tag[4..8].copy_from_slice(&m1.to_le_bytes());
        tag[8..12].copy_from_slice(&m2.to_le_bytes());
        tag[12..16].copy_from_slice(&m3.to_le_bytes());
        tag
    }
}

/// One-shot Poly1305 over `msg` with the 32-byte one-time key.
pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(msg);
    p.finish()
}

// --- ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8) ---------------------------

fn poly_key(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut block = [0u8; 64];
    chacha20_block(key, 0, nonce, &mut block);
    let mut k = [0u8; 32];
    k.copy_from_slice(&block[..32]);
    k
}

fn tag_over(one_time: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let zeros = [0u8; 16];
    let mut p = Poly1305::new(one_time);
    p.update(aad);
    let pad = (16 - (aad.len() % 16)) % 16;
    p.update(&zeros[..pad]);
    p.update(ciphertext);
    let pad = (16 - (ciphertext.len() % 16)) % 16;
    p.update(&zeros[..pad]);
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    p.update(&lens);
    p.finish()
}

/// Encrypt `buf` in place and return the authentication tag. `buf` holds the
/// plaintext on entry and the ciphertext on return.
pub fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; TAG_LEN] {
    let otk = poly_key(key, nonce);
    chacha20_xor(key, 1, nonce, buf);
    tag_over(&otk, aad, buf)
}

/// Verify `tag` and, if it matches, decrypt `buf` in place. Returns false and
/// leaves `buf` untouched on authentication failure.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    let otk = poly_key(key, nonce);
    let expect = tag_over(&otk, aad, buf);
    // Constant-time compare.
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= expect[i] ^ tag[i];
    }
    if diff != 0 {
        return false;
    }
    chacha20_xor(key, 1, nonce, buf);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> std::vec::Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8439 section 2.3.2 keystream block known-answer test.
    #[test]
    fn chacha20_block_kat() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = {
            let mut n = [0u8; 12];
            n[3] = 0x09;
            n[7] = 0x4a;
            n
        };
        let mut out = [0u8; 64];
        chacha20_block(&key, 1, &nonce, &mut out);
        let expect = hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(&out[..], &expect[..]);
    }

    // RFC 8439 section 2.4.2 encryption known-answer test.
    #[test]
    fn chacha20_encrypt_kat() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = {
            let mut n = [0u8; 12];
            n[3] = 0;
            n[7] = 0x4a;
            n
        };
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you \
            only one tip for the future, sunscreen would be it."
            .to_vec();
        chacha20_xor(&key, 1, &nonce, &mut buf);
        let expect = hex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(&buf[..], &expect[..]);
    }

    // RFC 8439 section 2.5.2 Poly1305 known-answer test.
    #[test]
    fn poly1305_kat() {
        let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(&k, msg);
        let expect = hex("a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(&tag[..], &expect[..]);
    }

    // RFC 8439 section 2.8.2 AEAD known-answer test.
    #[test]
    fn aead_seal_kat() {
        let key: [u8; 32] = core::array::from_fn(|i| (0x80 + i) as u8);
        let nonce = hex("070000004041424344454647");
        let mut n = [0u8; 12];
        n.copy_from_slice(&nonce);
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you \
            only one tip for the future, sunscreen would be it."
            .to_vec();
        let tag = aead_seal(&key, &n, &aad, &mut buf);
        let expect_ct = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expect_tag = hex("1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(&buf[..], &expect_ct[..], "ciphertext mismatch");
        assert_eq!(&tag[..], &expect_tag[..], "tag mismatch");
    }

    #[test]
    fn aead_round_trip_and_reject_tamper() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"session-42";
        let plain = b"the session key must never be recoverable from RAM";
        let mut buf = plain.to_vec();
        let tag = aead_seal(&key, &nonce, aad, &mut buf);
        assert_ne!(&buf[..], &plain[..], "ciphertext equals plaintext");

        // Tampered ciphertext is rejected.
        let mut bad = buf.clone();
        bad[0] ^= 1;
        assert!(!aead_open(&key, &nonce, aad, &mut bad, &tag));

        // Clean ciphertext decrypts back to the plaintext.
        assert!(aead_open(&key, &nonce, aad, &mut buf, &tag));
        assert_eq!(&buf[..], &plain[..]);
    }

    // The session key bytes must never appear inside the produced ciphertext.
    #[test]
    fn key_bytes_never_appear_in_ciphertext() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let nonce = [0u8; 12];
        // A long, low-entropy plaintext is the easiest case to accidentally leak
        // key material into, so encrypt 4 KiB of zeros and scan for the key.
        let mut buf = std::vec![0u8; 4096];
        let _ = aead_seal(&key, &nonce, b"", &mut buf);
        let found = buf.windows(key.len()).any(|w| w == &key[..]);
        assert!(!found, "key bytes leaked into ciphertext");
        // Also check every 8-byte contiguous run of the key.
        for start in 0..(key.len() - 8) {
            let needle = &key[start..start + 8];
            assert!(
                !buf.windows(8).any(|w| w == needle),
                "8-byte key run leaked at offset {start}"
            );
        }
    }
}
