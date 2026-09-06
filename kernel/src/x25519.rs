#![allow(dead_code)]

//! X25519 ECDH (RFC 7748) over GF(2^255-19), from scratch, no external crates,
//! pure `core`. The field is represented in five 51-bit limbs (radix 2^51) with
//! `u128` used for the multiply accumulators. The scalar multiplication is the
//! Montgomery ladder with constant-time conditional swap.

type Fe = [u64; 5];

const MASK: u64 = (1u64 << 51) - 1;

fn fe_zero() -> Fe {
    [0; 5]
}

fn fe_one() -> Fe {
    [1, 0, 0, 0, 0]
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
    // Two weak-reduction passes to bring every limb below 2^51.
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
    // Canonicalize: conditionally subtract p by the standard donna sequence.
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
    // a - b + 2p, keeping limbs positive.
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

fn fe_mul121665(a: &Fe) -> Fe {
    let m = MASK as u128;
    let mut r0 = a[0] as u128 * 121665;
    let mut r1 = a[1] as u128 * 121665;
    let mut r2 = a[2] as u128 * 121665;
    let mut r3 = a[3] as u128 * 121665;
    let mut r4 = a[4] as u128 * 121665;

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

fn fe_sq_times(a: &Fe, n: usize) -> Fe {
    let mut r = *a;
    for _ in 0..n {
        r = fe_sq(&r);
    }
    r
}

fn fe_invert(z: &Fe) -> Fe {
    // z^(p-2) via the canonical curve25519 addition chain.
    let a = fe_sq(z); // 2
    let t0 = fe_sq_times(&a, 2); // 8
    let b = fe_mul(&t0, z); // 9
    let a = fe_mul(&b, &a); // 11
    let t0 = fe_sq(&a); // 22
    let b = fe_mul(&t0, &b); // 2^5 - 2^0
    let t0 = fe_sq_times(&b, 5);
    let b = fe_mul(&t0, &b); // 2^10 - 2^0
    let t0 = fe_sq_times(&b, 10);
    let c = fe_mul(&t0, &b); // 2^20 - 2^0
    let t0 = fe_sq_times(&c, 20);
    let t0 = fe_mul(&t0, &c); // 2^40 - 2^0
    let t0 = fe_sq_times(&t0, 10);
    let b = fe_mul(&t0, &b); // 2^50 - 2^0
    let t0 = fe_sq_times(&b, 50);
    let c = fe_mul(&t0, &b); // 2^100 - 2^0
    let t0 = fe_sq_times(&c, 100);
    let t0 = fe_mul(&t0, &c); // 2^200 - 2^0
    let t0 = fe_sq_times(&t0, 50);
    let t0 = fe_mul(&t0, &b); // 2^250 - 2^0
    let t0 = fe_sq_times(&t0, 5);
    fe_mul(&t0, &a) // 2^255 - 21
}

fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

pub fn x25519(scalar: &[u8; 32], u_coordinate: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let mut ub = *u_coordinate;
    ub[31] &= 127;
    let x1 = fe_from_bytes(&ub);

    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = x1;
    let mut z3 = fe_one();
    let mut swap: u64 = 0;

    for t in (0..=254usize).rev() {
        let kt = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul121665(&e)));
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    let res = fe_mul(&x2, &fe_invert(&z2));
    fe_to_bytes(&res)
}

pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &BASEPOINT)
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

    #[test]
    fn rfc7748_section_5_2_vector_1() {
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected =
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_section_6_1_diffie_hellman() {
        let alice_priv =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(x25519_base(&alice_priv), alice_pub);

        let bob_priv =
            hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub =
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(x25519_base(&bob_priv), bob_pub);

        let shared =
            hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&alice_priv, &bob_pub), shared);
        assert_eq!(x25519(&bob_priv, &alice_pub), shared);
    }
}
