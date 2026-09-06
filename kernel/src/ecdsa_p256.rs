#![allow(dead_code)]
//! ECDSA signature verification on NIST P-256 (secp256r1), from scratch.
//!
//! Pure `core`, no `alloc`, no external crates. The field GF(p) and scalar field
//! GF(n) arithmetic run on the in-tree fixed-capacity big integer (`bigint`).
//! Curve points use Jacobian coordinates (X : Y : Z) standing for the affine
//! point (X/Z^2, Y/Z^3) so the double-and-add scalar multiply needs only one
//! modular inversion at the very end, not one per step.
//!
//! Only what TLS 1.3 server authentication needs is here: verify an (r, s)
//! signature against a public-key point and a message digest. There is no
//! signing, no key generation, and no secret-dependent branching requirement
//! (verification is all public data). It is checked on the host against the RFC
//! 6979 P-256/SHA-256 deterministic-signature known answers.

use crate::bigint::{self, Big};

// --- Curve constants (big-endian) --------------------------------------------

const P_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
const N_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const B_BE: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];
const GX_BE: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const GY_BE: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

fn p() -> Big {
    bigint::from_be_bytes(&P_BE)
}
fn n() -> Big {
    bigint::from_be_bytes(&N_BE)
}

// --- Field arithmetic mod p ---------------------------------------------------

fn fadd(a: &Big, b: &Big) -> Big {
    a.addmod(b, &p())
}
fn fsub(a: &Big, b: &Big) -> Big {
    a.submod(b, &p())
}
fn fmul(a: &Big, b: &Big) -> Big {
    a.mulmod(b, &p())
}
fn fsqr(a: &Big) -> Big {
    a.mulmod(a, &p())
}
fn fmul_small(a: &Big, k: u64) -> Big {
    a.mulmod(&bigint::from_u64(k), &p())
}

// --- Jacobian point (X : Y : Z), infinity is Z == 0 --------------------------

#[derive(Clone)]
struct Jac {
    x: Big,
    y: Big,
    z: Big,
}

fn jac_infinity() -> Jac {
    Jac { x: bigint::from_u64(1), y: bigint::from_u64(1), z: bigint::zero() }
}

fn jac_from_affine(x: Big, y: Big) -> Jac {
    Jac { x, y, z: bigint::from_u64(1) }
}

fn is_infinity(pt: &Jac) -> bool {
    pt.z.is_zero()
}

/// Point doubling in Jacobian coordinates (formula "dbl-2007-bl", valid for any
/// short-Weierstrass a; here a = p - 3).
fn jac_double(pt: &Jac) -> Jac {
    if is_infinity(pt) || pt.y.is_zero() {
        return jac_infinity();
    }
    let xx = fsqr(&pt.x); // X^2
    let yy = fsqr(&pt.y); // Y^2
    let yyyy = fsqr(&yy); // Y^4
    let zz = fsqr(&pt.z); // Z^2
    // S = 2*((X+YY)^2 - XX - YYYY)
    let xy = fadd(&pt.x, &yy);
    let s = fmul_small(&fsub(&fsub(&fsqr(&xy), &xx), &yyyy), 2);
    // M = 3*XX + a*ZZ^2, with a = -3  ->  M = 3*(XX - ZZ^2)
    let zzzz = fsqr(&zz);
    let m = fmul_small(&fsub(&xx, &zzzz), 3);
    // T = M^2 - 2*S
    let t = fsub(&fsqr(&m), &fmul_small(&s, 2));
    let x3 = t;
    // Y3 = M*(S - T) - 8*YYYY
    let y3 = fsub(&fmul(&m, &fsub(&s, &t)), &fmul_small(&yyyy, 8));
    // Z3 = 2*Y*Z  (== (Y+Z)^2 - YY - ZZ)
    let yz = fadd(&pt.y, &pt.z);
    let z3 = fsub(&fsub(&fsqr(&yz), &yy), &zz);
    Jac { x: x3, y: y3, z: z3 }
}

/// Point addition in Jacobian coordinates ("add-2007-bl"), with fallbacks to the
/// doubling formula and the point at infinity for the degenerate cases.
fn jac_add(a: &Jac, b: &Jac) -> Jac {
    if is_infinity(a) {
        return b.clone();
    }
    if is_infinity(b) {
        return a.clone();
    }
    let z1z1 = fsqr(&a.z);
    let z2z2 = fsqr(&b.z);
    let u1 = fmul(&a.x, &z2z2);
    let u2 = fmul(&b.x, &z1z1);
    let s1 = fmul(&fmul(&a.y, &b.z), &z2z2);
    let s2 = fmul(&fmul(&b.y, &a.z), &z1z1);
    if u1.cmp(&u2) == core::cmp::Ordering::Equal {
        if s1.cmp(&s2) == core::cmp::Ordering::Equal {
            return jac_double(a);
        }
        return jac_infinity();
    }
    let h = fsub(&u2, &u1);
    let i = fsqr(&fmul_small(&h, 2)); // (2H)^2
    let j = fmul(&h, &i);
    let r = fmul_small(&fsub(&s2, &s1), 2);
    let v = fmul(&u1, &i);
    // X3 = r^2 - J - 2V
    let x3 = fsub(&fsub(&fsqr(&r), &j), &fmul_small(&v, 2));
    // Y3 = r*(V - X3) - 2*S1*J
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fmul_small(&fmul(&s1, &j), 2));
    // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
    let zz = fsub(&fsub(&fsqr(&fadd(&a.z, &b.z)), &z1z1), &z2z2);
    let z3 = fmul(&zz, &h);
    Jac { x: x3, y: y3, z: z3 }
}

/// Scalar multiply `k * pt`, left-to-right double-and-add over the bits of `k`.
fn jac_mul(k: &Big, pt: &Jac) -> Jac {
    let mut acc = jac_infinity();
    let mut i = k.bit_len();
    while i > 0 {
        i -= 1;
        acc = jac_double(&acc);
        if k.bit_test(i) {
            acc = jac_add(&acc, pt);
        }
    }
    acc
}

/// Affine x-coordinate of a Jacobian point, reduced mod p. Returns `None` for the
/// point at infinity.
fn affine_x(pt: &Jac) -> Option<Big> {
    if is_infinity(pt) {
        return None;
    }
    let zz = fsqr(&pt.z);
    let zz_inv = zz.modinv(&p())?;
    Some(fmul(&pt.x, &zz_inv))
}

/// True if the affine point (x, y) satisfies y^2 = x^3 - 3x + b over GF(p).
fn on_curve(x: &Big, y: &Big) -> bool {
    let pp = p();
    if x.cmp(&pp) != core::cmp::Ordering::Less || y.cmp(&pp) != core::cmp::Ordering::Less {
        return false;
    }
    let b = bigint::from_be_bytes(&B_BE);
    let lhs = fsqr(y);
    // x^3 - 3x + b
    let x3 = fmul(&fsqr(x), x);
    let rhs = fadd(&fsub(&x3, &fmul_small(x, 3)), &b);
    lhs.cmp(&rhs) == core::cmp::Ordering::Equal
}

// --- Public API ---------------------------------------------------------------

/// Verify an ECDSA-P256 signature. `point` is the SEC1 uncompressed public key
/// (0x04 || X || Y, 65 bytes), `digest` the message hash (SHA-256, 32 bytes),
/// and `r`/`s` the signature integers as big-endian bytes. Returns true only on
/// a valid signature. Never panics.
pub fn verify(point: &[u8], digest: &[u8], r_bytes: &[u8], s_bytes: &[u8]) -> bool {
    if point.len() != 65 || point[0] != 0x04 {
        return false;
    }
    let qx = bigint::from_be_bytes(&point[1..33]);
    let qy = bigint::from_be_bytes(&point[33..65]);
    if !on_curve(&qx, &qy) {
        return false;
    }
    let order = n();
    let one = bigint::from_u64(1);
    let r = bigint::from_be_bytes(r_bytes);
    let s = bigint::from_be_bytes(s_bytes);
    // 1 <= r,s <= n-1
    if r.cmp(&one) == core::cmp::Ordering::Less || r.cmp(&order) != core::cmp::Ordering::Less {
        return false;
    }
    if s.cmp(&one) == core::cmp::Ordering::Less || s.cmp(&order) != core::cmp::Ordering::Less {
        return false;
    }
    // e = leftmost 256 bits of the digest (SHA-256 output is exactly 256 bits).
    let elen = core::cmp::min(digest.len(), 32);
    let e = bigint::from_be_bytes(&digest[..elen]);
    let w = match s.modinv(&order) {
        Some(w) => w,
        None => return false,
    };
    let u1 = e.mulmod(&w, &order);
    let u2 = r.mulmod(&w, &order);
    let g = jac_from_affine(bigint::from_be_bytes(&GX_BE), bigint::from_be_bytes(&GY_BE));
    let q = jac_from_affine(qx, qy);
    let rr = jac_add(&jac_mul(&u1, &g), &jac_mul(&u2, &q));
    let x = match affine_x(&rr) {
        Some(x) => x,
        None => return false,
    };
    let v = x.rem(&order);
    v.cmp(&r) == core::cmp::Ordering::Equal
}

/// Verify an ECDSA-P256 signature whose value is DER-encoded as
/// `SEQUENCE { r INTEGER, s INTEGER }` (the form used in TLS CertificateVerify
/// and in X.509 certificate signatures). Returns true only on a valid signature.
pub fn verify_der(point: &[u8], digest: &[u8], der_sig: &[u8]) -> bool {
    match parse_der_sig(der_sig) {
        Some((r, s)) => verify(point, digest, r, s),
        None => false,
    }
}

/// Parse `SEQUENCE { r INTEGER, s INTEGER }`, returning the raw big-endian
/// magnitude bytes of r and s (leading 0x00 sign padding stripped). Never panics.
fn parse_der_sig(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, body, _) = read_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (t_r, r, r_len) = read_tlv(body)?;
    if t_r != 0x02 {
        return None;
    }
    let (t_s, s, _) = read_tlv(body.get(r_len..)?)?;
    if t_s != 0x02 {
        return None;
    }
    Some((strip_sign(r), strip_sign(s)))
}

fn strip_sign(b: &[u8]) -> &[u8] {
    if b.first() == Some(&0x00) && b.len() > 1 {
        &b[1..]
    } else {
        b
    }
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
    use crate::sha2;

    fn hexb(s: &str) -> std::vec::Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RFC 6979 Appendix A.2.5, curve P-256, public key W = (Ux, Uy).
    const UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    const UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

    fn pubkey() -> std::vec::Vec<u8> {
        let mut p = std::vec![0x04u8];
        p.extend_from_slice(&hexb(UX));
        p.extend_from_slice(&hexb(UY));
        p
    }

    // RFC 6979 A.2.5, message "sample", SHA-256.
    #[test]
    fn rfc6979_p256_sha256_sample_good() {
        let e = sha2::sha256(b"sample");
        let r = hexb("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let s = hexb("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        assert!(verify(&pubkey(), &e, &r, &s), "known-good P-256/SHA-256 signature must verify");
    }

    // RFC 6979 A.2.5, message "test", SHA-256.
    #[test]
    fn rfc6979_p256_sha256_test_good() {
        let e = sha2::sha256(b"test");
        let r = hexb("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
        let s = hexb("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");
        assert!(verify(&pubkey(), &e, &r, &s), "second known-good vector must verify");
    }

    // A tampered signature (one byte of s flipped) must be rejected.
    #[test]
    fn tampered_signature_rejected() {
        let e = sha2::sha256(b"sample");
        let r = hexb("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let mut s = hexb("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        s[10] ^= 0x01;
        assert!(!verify(&pubkey(), &e, &r, &s), "tampered s must not verify");
    }

    // Wrong message digest must be rejected under a good signature.
    #[test]
    fn wrong_digest_rejected() {
        let e = sha2::sha256(b"not the signed message");
        let r = hexb("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let s = hexb("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        assert!(!verify(&pubkey(), &e, &r, &s), "signature over a different digest must not verify");
    }

    // r or s out of range [1, n-1] must be rejected.
    #[test]
    fn out_of_range_rejected() {
        let e = sha2::sha256(b"sample");
        let zero = [0u8; 32];
        let s = hexb("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
        assert!(!verify(&pubkey(), &e, &zero, &s), "r = 0 must be rejected");
    }

    // The DER wrapper must decode to the same accept/reject decisions.
    #[test]
    fn der_encoded_signature() {
        let e = sha2::sha256(b"sample");
        // SEQUENCE { INTEGER r, INTEGER s } for the A.2.5 "sample" signature.
        let der = hexb(
            "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716\
             022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        );
        assert!(verify_der(&pubkey(), &e, &der), "DER-wrapped good signature must verify");
        let mut bad = der.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(!verify_der(&pubkey(), &e, &bad), "DER-wrapped tampered signature must not verify");
    }
}
