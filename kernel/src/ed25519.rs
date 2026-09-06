#![allow(dead_code)]

//! Ed25519 signature verification (RFC 8032) over edwards25519, from scratch,
//! pure `core`, no external crates. SHA-512 is taken from the existing kernel
//! `sha2` module (never reimplemented). The base field GF(2^255-19) is the same
//! prime as X25519; it is reimplemented here in five 51-bit limbs so this module
//! is self-contained. Point arithmetic uses extended (projective) Edwards
//! coordinates with the complete unified addition formula for a = -1.

type Fe = [u64; 5];

const MASK: u64 = (1u64 << 51) - 1;

// Exponent (p-5)/8 = 2^252 - 3, little-endian.
const EXP_P58: [u8; 32] = {
    let mut e = [0xffu8; 32];
    e[0] = 0xfd;
    e[31] = 0x0f;
    e
};

// Exponent (p-1)/4 = 2^253 - 5, little-endian (used to build sqrt(-1)).
const EXP_P14: [u8; 32] = {
    let mut e = [0xffu8; 32];
    e[0] = 0xfb;
    e[31] = 0x1f;
    e
};

// Group order L = 2^252 + 27742317777372353535851937790883648493, radix 2^64.
const L: [u64; 5] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
    0x0000000000000000,
];

fn fe_zero() -> Fe {
    [0; 5]
}

fn fe_one() -> Fe {
    [1, 0, 0, 0, 0]
}

fn fe_from_u64(n: u64) -> Fe {
    [n, 0, 0, 0, 0]
}

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut w = [0u64; 4];
    for i in 0..4 {
        let mut c = [0u8; 8];
        c.copy_from_slice(&b[i * 8..i * 8 + 8]);
        w[i] = u64::from_le_bytes(c);
    }
    [
        w[0] & MASK,
        ((w[0] >> 51) | (w[1] << 13)) & MASK,
        ((w[1] >> 38) | (w[2] << 26)) & MASK,
        ((w[2] >> 25) | (w[3] << 39)) & MASK,
        (w[3] >> 12) & MASK,
    ]
}

fn fe_to_bytes(input: &Fe) -> [u8; 32] {
    let mut t = *input;
    for _ in 0..2 {
        let c = t[0] >> 51;
        t[0] &= MASK;
        t[1] += c;
        let c = t[1] >> 51;
        t[1] &= MASK;
        t[2] += c;
        let c = t[2] >> 51;
        t[2] &= MASK;
        t[3] += c;
        let c = t[3] >> 51;
        t[3] &= MASK;
        t[4] += c;
        let c = t[4] >> 51;
        t[4] &= MASK;
        t[0] += c * 19;
    }
    t[0] += 19;
    let c = t[0] >> 51;
    t[0] &= MASK;
    t[1] += c;
    let c = t[1] >> 51;
    t[1] &= MASK;
    t[2] += c;
    let c = t[2] >> 51;
    t[2] &= MASK;
    t[3] += c;
    let c = t[3] >> 51;
    t[3] &= MASK;
    t[4] += c;
    let c = t[4] >> 51;
    t[4] &= MASK;
    t[0] += c * 19;

    t[0] += 0x8000000000000 - 19;
    t[1] += 0x8000000000000 - 1;
    t[2] += 0x8000000000000 - 1;
    t[3] += 0x8000000000000 - 1;
    t[4] += 0x8000000000000 - 1;

    let c = t[0] >> 51;
    t[0] &= MASK;
    t[1] += c;
    let c = t[1] >> 51;
    t[1] &= MASK;
    t[2] += c;
    let c = t[2] >> 51;
    t[2] &= MASK;
    t[3] += c;
    let c = t[3] >> 51;
    t[3] &= MASK;
    t[4] += c;
    t[4] &= MASK;

    let w0 = t[0] | (t[1] << 51);
    let w1 = (t[1] >> 13) | (t[2] << 38);
    let w2 = (t[2] >> 26) | (t[3] << 25);
    let w3 = (t[3] >> 39) | (t[4] << 12);
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&w0.to_le_bytes());
    out[8..16].copy_from_slice(&w1.to_le_bytes());
    out[16..24].copy_from_slice(&w2.to_le_bytes());
    out[24..32].copy_from_slice(&w3.to_le_bytes());
    out
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + 0xFFFFFFFFFFFDA - b[0],
        a[1] + 0xFFFFFFFFFFFFE - b[1],
        a[2] + 0xFFFFFFFFFFFFE - b[2],
        a[3] + 0xFFFFFFFFFFFFE - b[3],
        a[4] + 0xFFFFFFFFFFFFE - b[4],
    ]
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;

    let mut r0 = a0 * b0 + 19 * (a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1);
    let mut r1 = a0 * b1 + a1 * b0 + 19 * (a2 * b4 + a3 * b3 + a4 * b2);
    let mut r2 = a0 * b2 + a1 * b1 + a2 * b0 + 19 * (a3 * b4 + a4 * b3);
    let mut r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + 19 * (a4 * b4);
    let mut r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    let m = MASK as u128;
    let c = r0 >> 51;
    r0 &= m;
    r1 += c;
    let c = r1 >> 51;
    r1 &= m;
    r2 += c;
    let c = r2 >> 51;
    r2 &= m;
    r3 += c;
    let c = r3 >> 51;
    r3 &= m;
    r4 += c;
    let c = r4 >> 51;
    r4 &= m;
    r0 += c * 19;
    let c = r0 >> 51;
    r0 &= m;
    r1 += c;

    [r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64]
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_carry(a: &Fe) -> Fe {
    let mut t = *a;
    let c = t[0] >> 51;
    t[0] &= MASK;
    t[1] += c;
    let c = t[1] >> 51;
    t[1] &= MASK;
    t[2] += c;
    let c = t[2] >> 51;
    t[2] &= MASK;
    t[3] += c;
    let c = t[3] >> 51;
    t[3] &= MASK;
    t[4] += c;
    let c = t[4] >> 51;
    t[4] &= MASK;
    t[0] += c * 19;
    let c = t[0] >> 51;
    t[0] &= MASK;
    t[1] += c;
    t
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&fe_zero(), &fe_carry(a))
}

fn fe_sq_times(a: &Fe, n: usize) -> Fe {
    let mut r = *a;
    for _ in 0..n {
        r = fe_sq(&r);
    }
    r
}

fn fe_invert(z: &Fe) -> Fe {
    let a = fe_sq(z);
    let t0 = fe_sq_times(&a, 2);
    let b = fe_mul(&t0, z);
    let a = fe_mul(&b, &a);
    let t0 = fe_sq(&a);
    let b = fe_mul(&t0, &b);
    let t0 = fe_sq_times(&b, 5);
    let b = fe_mul(&t0, &b);
    let t0 = fe_sq_times(&b, 10);
    let c = fe_mul(&t0, &b);
    let t0 = fe_sq_times(&c, 20);
    let t0 = fe_mul(&t0, &c);
    let t0 = fe_sq_times(&t0, 10);
    let b = fe_mul(&t0, &b);
    let t0 = fe_sq_times(&b, 50);
    let c = fe_mul(&t0, &b);
    let t0 = fe_sq_times(&c, 100);
    let t0 = fe_mul(&t0, &c);
    let t0 = fe_sq_times(&t0, 50);
    let t0 = fe_mul(&t0, &b);
    let t0 = fe_sq_times(&t0, 5);
    fe_mul(&t0, &a)
}

fn fe_pow(base: &Fe, exp: &[u8; 32]) -> Fe {
    let mut r = fe_one();
    for i in (0..256usize).rev() {
        r = fe_sq(&r);
        if (exp[i >> 3] >> (i & 7)) & 1 == 1 {
            r = fe_mul(&r, base);
        }
    }
    r
}

fn fe_eq(a: &Fe, b: &Fe) -> bool {
    fe_to_bytes(a) == fe_to_bytes(b)
}

fn fe_is_zero(a: &Fe) -> bool {
    fe_to_bytes(a) == [0u8; 32]
}

fn fe_lsb(a: &Fe) -> u8 {
    fe_to_bytes(a)[0] & 1
}

fn edwards_d() -> Fe {
    // d = -121665 / 121666 mod p
    let num = fe_neg(&fe_from_u64(121665));
    let den = fe_invert(&fe_from_u64(121666));
    fe_mul(&num, &den)
}

fn sqrt_m1() -> Fe {
    // sqrt(-1) = 2^((p-1)/4) mod p
    fe_pow(&fe_from_u64(2), &EXP_P14)
}

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn point_identity() -> Point {
    Point {
        x: fe_zero(),
        y: fe_one(),
        z: fe_one(),
        t: fe_zero(),
    }
}

fn point_add(p: &Point, q: &Point, d2: &Fe) -> Point {
    let a = fe_mul(&fe_sub(&p.y, &p.x), &fe_sub(&q.y, &q.x));
    let b = fe_mul(&fe_add(&p.y, &p.x), &fe_add(&q.y, &q.x));
    let c = fe_mul(&fe_mul(&p.t, d2), &q.t);
    let zz = fe_mul(&p.z, &q.z);
    let dd = fe_add(&zz, &zz);
    let e = fe_sub(&b, &a);
    let f = fe_sub(&dd, &c);
    let g = fe_add(&dd, &c);
    let h = fe_add(&b, &a);
    Point {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        t: fe_mul(&e, &h),
        z: fe_mul(&f, &g),
    }
}

fn scalar_mul(scalar: &[u8; 32], p: &Point, d2: &Fe) -> Point {
    let mut r = point_identity();
    for i in (0..256usize).rev() {
        r = point_add(&r, &r, d2);
        if (scalar[i >> 3] >> (i & 7)) & 1 == 1 {
            r = point_add(&r, p, d2);
        }
    }
    r
}

fn point_encode(p: &Point) -> [u8; 32] {
    let zinv = fe_invert(&p.z);
    let x = fe_mul(&p.x, &zinv);
    let y = fe_mul(&p.y, &zinv);
    let mut s = fe_to_bytes(&y);
    s[31] |= fe_lsb(&x) << 7;
    s
}

fn point_decompress(comp: &[u8; 32], d: &Fe, sqm1: &Fe) -> Option<Point> {
    let sign = comp[31] >> 7;
    let mut yb = *comp;
    yb[31] &= 0x7f;
    let y = fe_from_bytes(&yb);
    // Reject non-canonical y (y >= p).
    if fe_to_bytes(&y) != yb {
        return None;
    }

    let yy = fe_sq(&y);
    let u = fe_sub(&yy, &fe_one());
    let v = fe_add(&fe_mul(d, &yy), &fe_one());

    let v3 = fe_mul(&fe_sq(&v), &v);
    let v7 = fe_mul(&fe_sq(&v3), &v);
    let uv7 = fe_mul(&u, &v7);
    let pow = fe_pow(&uv7, &EXP_P58);
    let mut x = fe_mul(&fe_mul(&u, &v3), &pow);

    let vxx = fe_mul(&v, &fe_sq(&x));
    if fe_eq(&vxx, &u) {
        // x is already a root
    } else if fe_eq(&vxx, &fe_neg(&u)) {
        x = fe_mul(&x, sqm1);
    } else {
        return None;
    }

    if fe_is_zero(&x) && sign == 1 {
        return None;
    }
    if fe_lsb(&x) != sign {
        x = fe_neg(&x);
    }

    let t = fe_mul(&x, &y);
    Some(Point {
        x,
        y,
        z: fe_one(),
        t,
    })
}

fn scalar_less_than_l(s: &[u8; 32]) -> bool {
    let mut a = [0u64; 5];
    for i in 0..4 {
        let mut c = [0u8; 8];
        c.copy_from_slice(&s[i * 8..i * 8 + 8]);
        a[i] = u64::from_le_bytes(c);
    }
    for i in (0..5).rev() {
        if a[i] < L[i] {
            return true;
        }
        if a[i] > L[i] {
            return false;
        }
    }
    false
}

// Reduce a big-endian-processed value mod L via Horner's method over the
// little-endian input bytes. Big integers are held as five 64-bit limbs.
fn reduce_mod_l(input: &[u8]) -> [u8; 32] {
    let mut acc = [0u64; 5];
    for &byte in input.iter().rev() {
        // acc = acc * 256 + byte
        let mut carry = byte as u128;
        for limb in acc.iter_mut() {
            let v = (*limb as u128) * 256 + carry;
            *limb = v as u64;
            carry = v >> 64;
        }
        // Reduce mod L by conditional subtraction until acc < L.
        while !big_less_than(&acc, &L) {
            big_sub_assign(&mut acc, &L);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&acc[i].to_le_bytes());
    }
    out
}

fn big_less_than(a: &[u64; 5], b: &[u64; 5]) -> bool {
    for i in (0..5).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

fn big_sub_assign(a: &mut [u64; 5], b: &[u64; 5]) {
    let mut borrow = 0i128;
    for i in 0..5 {
        let v = a[i] as i128 - b[i] as i128 - borrow;
        if v < 0 {
            a[i] = (v + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            a[i] = v as u64;
            borrow = 0;
        }
    }
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..64]);
    if !scalar_less_than_l(&s) {
        return false;
    }
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[0..32]);

    let d = edwards_d();
    let d2 = fe_add(&d, &d);
    let sqm1 = sqrt_m1();

    let a_point = match point_decompress(public_key, &d, &sqm1) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match point_decompress(&r_bytes, &d, &sqm1) {
        Some(p) => p,
        None => return false,
    };

    // k = SHA512(R || A || M) mod L, hashed incrementally to avoid allocation.
    let mut hasher = crate::sha2::Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let hash = hasher.finalize();
    let k = reduce_mod_l(&hash);

    // Base point B (compressed encoding).
    let mut b_comp = [0x66u8; 32];
    b_comp[0] = 0x58;
    let base = match point_decompress(&b_comp, &d, &sqm1) {
        Some(p) => p,
        None => return false,
    };

    // Check [s]B == R + [k]A.
    let lhs = scalar_mul(&s, &base, &d2);
    let ka = scalar_mul(&k, &a_point, &d2);
    let rhs = point_add(&r_point, &ka, &d2);

    point_encode(&lhs) == point_encode(&rhs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn hex64(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for i in 0..64 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc8032_test1_empty_message() {
        let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = hex64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert!(verify(&pk, &[], &sig));
    }

    #[test]
    fn rfc8032_test1_tamper_fails() {
        let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let mut sig = hex64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        // Tamper: flip one bit of the signature.
        sig[10] ^= 0x01;
        assert!(!verify(&pk, &[], &sig));
        // Tamper via the message on an otherwise-valid signature.
        let good = hex64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert!(!verify(&pk, &[0x00], &good));
    }

    #[test]
    fn rfc8032_test2_one_byte() {
        let pk = hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig = hex64(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let msg = [0x72u8];
        assert!(verify(&pk, &msg, &sig));
    }

    #[test]
    fn rfc8032_test3_two_bytes() {
        let pk = hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let sig = hex64(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
        let msg = [0xaf, 0x82u8];
        assert!(verify(&pk, &msg, &sig));
    }
}
