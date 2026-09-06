#![allow(dead_code)]
//! RSA signature verification, from scratch, on the in-tree big integer.
//!
//! Pure `core`, no `alloc`, no external crates. Two schemes are provided, both
//! with SHA-256:
//!
//!   * PKCS#1 v1.5 (`verify_pkcs1_sha256`), used for X.509 certificate-chain
//!     signatures (`sha256WithRSAEncryption`).
//!   * PSS with MGF1-SHA256 and a 32-byte salt (`verify_pss_sha256`), used for the
//!     TLS 1.3 CertificateVerify scheme `rsa_pss_rsae_sha256`.
//!
//! The public key is taken as the DER `RSAPublicKey ::= SEQUENCE { modulus,
//! publicExponent }`, which is exactly the subjectPublicKey contents of an RSA
//! `SubjectPublicKeyInfo` (`x509::Cert::spki_key` for an RSA cert). The RSA
//! primitive is `s^e mod n` via `bigint::modexp`; everything else is padding and
//! digest checking. Never panics on malformed input; every failure returns false.

use crate::bigint::{self, Big};
use crate::sha2;

/// DigestInfo prefix for SHA-256 (RFC 8017 9.2, the fixed DER header before the
/// 32-byte hash in a PKCS#1 v1.5 signature).
const SHA256_DIGESTINFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const HLEN: usize = 32; // SHA-256 output length

/// Parse `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`,
/// returning the modulus and exponent as big integers. Leading 0x00 sign padding
/// is handled by `from_be_bytes`. Returns `None` on malformed DER.
fn parse_pubkey(der: &[u8]) -> Option<(Big, Big, usize)> {
    let (tag, body, _) = read_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (t_n, n_bytes, n_consumed) = read_tlv(body)?;
    if t_n != 0x02 {
        return None;
    }
    let (t_e, e_bytes, _) = read_tlv(body.get(n_consumed..)?)?;
    if t_e != 0x02 {
        return None;
    }
    // Modulus byte length (k), with any single leading zero sign byte removed.
    let n_mag = if n_bytes.first() == Some(&0x00) { &n_bytes[1..] } else { n_bytes };
    let n = bigint::from_be_bytes(n_mag);
    let e = bigint::from_be_bytes(e_bytes);
    Some((n, e, n_mag.len()))
}

/// The RSA verification primitive: `m = s^e mod n`, encoded big-endian into a
/// `k`-byte buffer (`EM`). Returns `None` if the signature is out of range.
fn rsavp1(n: &Big, e: &Big, sig: &[u8], k: usize, out: &mut [u8]) -> Option<()> {
    let s = bigint::from_be_bytes(sig);
    // s must be in [0, n-1].
    if s.cmp(n) != core::cmp::Ordering::Less {
        return None;
    }
    let m = s.modexp(e, n);
    if out.len() < k {
        return None;
    }
    m.to_be_bytes(&mut out[..k]);
    Some(())
}

/// Verify an RSA PKCS#1 v1.5 signature over SHA-256(`msg`). `pubkey_der` is the
/// DER RSAPublicKey. Returns true only on a valid signature.
pub fn verify_pkcs1_sha256(pubkey_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (n, e, k) = match parse_pubkey(pubkey_der) {
        Some(v) => v,
        None => return false,
    };
    if sig.len() != k || k < HLEN + SHA256_DIGESTINFO.len() + 11 {
        return false;
    }
    let mut em = [0u8; 512];
    if k > em.len() || rsavp1(&n, &e, sig, k, &mut em).is_none() {
        return false;
    }
    let em = &em[..k];
    let hash = sha2::sha256(msg);
    // EM = 0x00 || 0x01 || PS (0xFF..) || 0x00 || DigestInfo || H
    let t_len = SHA256_DIGESTINFO.len() + HLEN;
    let ps_len = k - 3 - t_len;
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut ok = true;
    for &b in &em[2..2 + ps_len] {
        if b != 0xff {
            ok = false;
        }
    }
    if !ok || em[2 + ps_len] != 0x00 {
        return false;
    }
    let di = &em[3 + ps_len..3 + ps_len + SHA256_DIGESTINFO.len()];
    let h = &em[3 + ps_len + SHA256_DIGESTINFO.len()..];
    ct_eq(di, &SHA256_DIGESTINFO) && ct_eq(h, &hash)
}

/// MGF1 with SHA-256: fill `out` with the mask derived from `seed`.
fn mgf1_sha256(seed: &[u8], out: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut done = 0;
    while done < out.len() {
        let mut h = sha2::Sha256::new();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        let block = h.finalize();
        let take = core::cmp::min(HLEN, out.len() - done);
        out[done..done + take].copy_from_slice(&block[..take]);
        done += take;
        counter += 1;
    }
}

/// Verify an RSA-PSS signature (MGF1-SHA256, salt length 32) over SHA-256(`msg`).
/// `pubkey_der` is the DER RSAPublicKey. Returns true only on a valid signature.
pub fn verify_pss_sha256(pubkey_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (n, e, k) = match parse_pubkey(pubkey_der) {
        Some(v) => v,
        None => return false,
    };
    if sig.len() != k {
        return false;
    }
    let mod_bits = n.bit_len();
    // emBits = modBits - 1; emLen = ceil(emBits / 8).
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let mut em_buf = [0u8; 512];
    if em_len == 0 || em_len > em_buf.len() || k > em_buf.len() {
        return false;
    }
    // rsavp1 writes k bytes; EM is the low em_len bytes of that (they are equal
    // when modBits-1 is a multiple of 8 plus one, i.e. em_len == k for common
    // key sizes; otherwise EM is the trailing em_len bytes).
    let mut full = [0u8; 512];
    if rsavp1(&n, &e, sig, k, &mut full).is_none() {
        return false;
    }
    let em = &full[k - em_len..k];
    em_buf[..em_len].copy_from_slice(em);
    let em = &mut em_buf[..em_len];

    let s_len = HLEN;
    if em_len < HLEN + s_len + 2 {
        return false;
    }
    if em[em_len - 1] != 0xbc {
        return false;
    }
    let db_len = em_len - HLEN - 1;
    // Split maskedDB || H.
    let mut h = [0u8; HLEN];
    h.copy_from_slice(&em[db_len..db_len + HLEN]);
    // The leftmost (8*emLen - emBits) bits of maskedDB must be zero.
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 && (em[0] >> (8 - top_bits)) != 0 {
        return false;
    }
    // DB = maskedDB XOR MGF1(H, db_len).
    let mut db_mask = [0u8; 512];
    mgf1_sha256(&h, &mut db_mask[..db_len]);
    let mut db = [0u8; 512];
    for i in 0..db_len {
        db[i] = em[i] ^ db_mask[i];
    }
    // Clear the leftmost top_bits of DB[0].
    if top_bits > 0 {
        db[0] &= 0xff >> top_bits;
    }
    // DB = PS (0x00..) || 0x01 || salt.
    let ps_len = db_len - s_len - 1;
    for &b in &db[..ps_len] {
        if b != 0x00 {
            return false;
        }
    }
    if db[ps_len] != 0x01 {
        return false;
    }
    let salt = &db[ps_len + 1..db_len];
    // H' = SHA256(0x00*8 || mHash || salt).
    let m_hash = sha2::sha256(msg);
    let mut hh = sha2::Sha256::new();
    hh.update(&[0u8; 8]);
    hh.update(&m_hash);
    hh.update(salt);
    let h_prime = hh.finalize();
    ct_eq(&h_prime, &h)
}

/// Constant-time-ish byte comparison (length must match).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Read one definite-length DER TLV. Returns (tag, content, total_consumed).
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let num = (first & 0x7f) as usize;
        if num == 0 || num > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..num {
            l = (l << 8) | (*input.get(2 + i)? as usize);
        }
        (l, 2 + num)
    };
    let end = hdr.checked_add(len)?;
    let content = input.get(hdr..end)?;
    Some((tag, content, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexb(s: &str) -> std::vec::Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RSA-2048 public key (DER RSAPublicKey) generated with OpenSSL.
    const PUB: &str = "3082010a0282010100aa2e39fc32e15e18980fdc500f643824aa5cd2dd96c1b2e672f3fd487bd7623463dfe5a71f43d8f6071ab05b91dbd7e0fc3834b97f1ecbcb3e51d12c76efe61f7c7816a74655afd1af1edaaa53069a43841415020c0f8811d40ebb07ad4566018191367b233bb7870442ba189f0bb4f8d7bf853835da2dd0423fc90a29b900a25c906924e75e1655d61de1fbf1dc2cc98a0af2663ebb4ff17a1790c46001e9ceda475e9e4a4fca4cab1880159eb6dc7e9804e593bacdc9a35b8b4b7f6128a2db24936d66550a80477ac769e5287f727c4da38856487f7fc02548590185296e3320c55b29e84502145b527a54475e14acb1994b8c1f1c27630c508d2ec4937bf30203010001";
    const MSG: &str = "6175726f726120727361206b6e6f776e2d616e737765722074657374206d657373616765";
    const PKCS1_SIG: &str = "02e5475a51a155fc5874ceb72b1c98b4655985530638c8266c0aa4bd2d09df0823d42332e06a6d768cb0e7b5c3804ca94de947b3c389175fc7d7b13d8f724d9fbab6c0555bfa1d16a81ef356ca8d5e552f5bfcd24bb989e924c7f1991ef7de484acca3116e03fa5e1a31de807114659280b6b287ad496f68eacdc3d0fcbc52fc67703a33941ce31ca367901efd90f38dee226d063dcd404ecc4a970c2d4153833b2056dd4009e2506e4e117961652474282b88e496bc11249985b5d32ecea3a5ba19cab515ac30aea1762287caea5e112744dfab95a93e6def3c0712cf6671bd5ef7a949d46d86873d84a834394574b3f1ee10d68adf75573d2c9aac9967f9ae";
    const PSS_SIG: &str = "54534ccc7b53c6b7a019354ec30db6993844fccfbef76dd5105ec7927bf12ad83dd8e4d36114b0470ee413cd17ea61d515c9d743c9710172ade42c39c42bd060a44ae94524c1f83f6c9b8562dcab1c3d39cb0d26aef06f62d10aeccdcd763e63e0f5b224ffc3ab75b10f61e9ce0c9d052efaea56b0e00094775837ae27f335e39f124c454d0286900d310022487e5f94b0e88e564790c275d77d24b723d53e5d972a0ee93e7764a823b671f2a90d34bec2e271c5d33e38f29010b7963a184c350225ffd330a4c6cf8ee41cab2aa41cd12461bed4659ecfe325eb03c79e651dd39c19fc989e19091d7e3163f8ef4c973ba65a8aa1763fb8ce720cd16cdba2c9a2";

    #[test]
    fn pkcs1_v15_good() {
        assert!(verify_pkcs1_sha256(&hexb(PUB), &hexb(MSG), &hexb(PKCS1_SIG)));
    }

    #[test]
    fn pkcs1_v15_tampered_rejected() {
        let mut sig = hexb(PKCS1_SIG);
        sig[100] ^= 0x01;
        assert!(!verify_pkcs1_sha256(&hexb(PUB), &hexb(MSG), &sig));
    }

    #[test]
    fn pkcs1_v15_wrong_message_rejected() {
        assert!(!verify_pkcs1_sha256(&hexb(PUB), b"different message", &hexb(PKCS1_SIG)));
    }

    #[test]
    fn pss_good() {
        assert!(verify_pss_sha256(&hexb(PUB), &hexb(MSG), &hexb(PSS_SIG)));
    }

    #[test]
    fn pss_tampered_rejected() {
        let mut sig = hexb(PSS_SIG);
        sig[100] ^= 0x01;
        assert!(!verify_pss_sha256(&hexb(PUB), &hexb(MSG), &sig));
    }

    #[test]
    fn pss_wrong_message_rejected() {
        assert!(!verify_pss_sha256(&hexb(PUB), b"different message", &hexb(PSS_SIG)));
    }

    // A PKCS#1 v1.5 signature must not verify under the PSS verifier and vice
    // versa: the padding schemes are distinct.
    #[test]
    fn schemes_do_not_cross_verify() {
        assert!(!verify_pss_sha256(&hexb(PUB), &hexb(MSG), &hexb(PKCS1_SIG)));
        assert!(!verify_pkcs1_sha256(&hexb(PUB), &hexb(MSG), &hexb(PSS_SIG)));
    }
}
