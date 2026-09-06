#![allow(dead_code)]
//! Fixed-capacity big-integer modular arithmetic, from scratch.
//!
//! Pure `core`, no `alloc`, no external crates. Provides exactly the operations
//! needed for P-256 ECDSA verify and RSA verify up to RSA-4096: comparison,
//! add/sub/mul, Knuth Algorithm D long division, and modular add/sub/mul/exp/inv.
//!
//! Values are stored little-endian in `u64` limbs with a tracked significant
//! length so arithmetic on small operands (e.g. 4-limb P-256 field elements)
//! runs in O(len^2), not O(LIMBS^2). Every result is kept normalized: `len` is
//! the exact number of significant limbs, all limbs at or above `len` are zero,
//! and the value zero has `len == 0`.

use core::cmp::Ordering;

/// Limb capacity. 64 limbs hold a 4096-bit modulus; 128 limbs hold the product
/// of two such; the remaining limbs are headroom for normalization scratch.
pub const LIMBS: usize = 136;

/// A fixed-capacity non-negative big integer.
#[derive(Clone, Copy)]
pub struct Big {
    limbs: [u64; LIMBS],
    /// Count of significant limbs; `0` for the value zero. Limbs `>= len` are 0.
    len: usize,
}

impl Big {
    fn normalize(&mut self) {
        while self.len > 0 && self.limbs[self.len - 1] == 0 {
            self.len -= 1;
        }
    }

    /// Test bit `i` (0 = least significant). Out-of-range bits read as 0.
    fn bit(&self, i: usize) -> bool {
        let limb = i / 64;
        if limb >= self.len {
            return false;
        }
        (self.limbs[limb] >> (i % 64)) & 1 == 1
    }

    /// Subtract assuming `self >= other`. Caller guarantees ordering.
    fn sub_unchecked(&self, other: &Big) -> Big {
        let mut r = zero();
        let mut borrow = 0u128;
        let n = self.len;
        let mut i = 0;
        while i < n {
            let a = self.limbs[i] as u128;
            let b = if i < other.len { other.limbs[i] as u128 } else { 0 };
            let cur = a.wrapping_sub(b).wrapping_sub(borrow);
            r.limbs[i] = cur as u64;
            borrow = (cur >> 64) & 1;
            i += 1;
        }
        r.len = n;
        r.normalize();
        r
    }
}

/// The value zero.
pub fn zero() -> Big {
    Big { limbs: [0u64; LIMBS], len: 0 }
}

/// A big integer holding a single `u64`.
pub fn from_u64(v: u64) -> Big {
    let mut r = zero();
    if v != 0 {
        r.limbs[0] = v;
        r.len = 1;
    }
    r
}

/// Interpret `b` as a big-endian unsigned integer.
///
/// If `b` is longer than `LIMBS * 8` bytes, only the low (least significant)
/// `LIMBS * 8` bytes are used; higher bytes are ignored. A real RSA-4096 modulus
/// is 512 bytes and fits with room to spare.
pub fn from_be_bytes(b: &[u8]) -> Big {
    let mut r = zero();
    let maxbytes = LIMBS * 8;
    let bytes = if b.len() > maxbytes { &b[b.len() - maxbytes..] } else { b };
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        let byte = bytes[n - 1 - i] as u64;
        let limb = i / 8;
        let shift = (i % 8) * 8;
        r.limbs[limb] |= byte << shift;
        i += 1;
    }
    r.len = LIMBS;
    r.normalize();
    r
}

impl Big {
    /// Write the value big-endian into `out`, left-zero-padded to `out.len()`.
    ///
    /// If the value needs more bytes than `out.len()`, only the low `out.len()`
    /// bytes are written (the high bytes are dropped).
    #[allow(clippy::wrong_self_convention)]
    pub fn to_be_bytes(&self, out: &mut [u8]) {
        let n = out.len();
        let mut i = 0;
        while i < n {
            let limb = i / 8;
            let shift = (i % 8) * 8;
            let byte = if limb < self.len {
                (self.limbs[limb] >> shift) as u8
            } else {
                0
            };
            out[n - 1 - i] = byte;
            i += 1;
        }
    }

    /// Number of significant bits (0 for the value zero).
    pub fn bit_len(&self) -> usize {
        if self.len == 0 {
            return 0;
        }
        let top = self.limbs[self.len - 1];
        (self.len - 1) * 64 + (64 - top.leading_zeros() as usize)
    }

    pub fn is_zero(&self) -> bool {
        self.len == 0
    }

    /// Test bit `i` (0 = least significant). Out-of-range bits read as 0.
    pub fn bit_test(&self, i: usize) -> bool {
        self.bit(i)
    }

    pub fn is_even(&self) -> bool {
        self.len == 0 || (self.limbs[0] & 1 == 0)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn cmp(&self, other: &Big) -> Ordering {
        if self.len != other.len {
            return self.len.cmp(&other.len);
        }
        let mut i = self.len;
        while i > 0 {
            i -= 1;
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        Ordering::Equal
    }

    pub fn add(&self, other: &Big) -> Big {
        let mut r = zero();
        let n = self.len.max(other.len);
        let mut carry = 0u128;
        let mut i = 0;
        while i < n {
            let a = if i < self.len { self.limbs[i] as u128 } else { 0 };
            let b = if i < other.len { other.limbs[i] as u128 } else { 0 };
            let s = a + b + carry;
            r.limbs[i] = s as u64;
            carry = s >> 64;
            i += 1;
        }
        if carry != 0 && n < LIMBS {
            r.limbs[n] = carry as u64;
            r.len = n + 1;
        } else {
            r.len = n;
        }
        r.normalize();
        r
    }

    /// Subtract, requiring `self >= other`. Returns zero if `other > self`
    /// (use [`Big::checked_sub`] to detect that case).
    pub fn sub(&self, other: &Big) -> Big {
        self.checked_sub(other).unwrap_or_else(zero)
    }

    pub fn checked_sub(&self, other: &Big) -> Option<Big> {
        if self.cmp(other) == Ordering::Less {
            None
        } else {
            Some(self.sub_unchecked(other))
        }
    }

    /// Schoolbook multiply. The result length (`self.len + other.len`) must fit
    /// within `LIMBS`; limbs beyond capacity are dropped.
    pub fn mul(&self, other: &Big) -> Big {
        let mut r = zero();
        if self.len == 0 || other.len == 0 {
            return r;
        }
        let mut i = 0;
        while i < self.len {
            let ai = self.limbs[i] as u128;
            let mut carry = 0u128;
            let mut j = 0;
            while j < other.len {
                let idx = i + j;
                if idx >= LIMBS {
                    break;
                }
                let prod = ai * (other.limbs[j] as u128) + (r.limbs[idx] as u128) + carry;
                r.limbs[idx] = prod as u64;
                carry = prod >> 64;
                j += 1;
            }
            let mut idx = i + other.len;
            while carry != 0 && idx < LIMBS {
                let cur = (r.limbs[idx] as u128) + carry;
                r.limbs[idx] = cur as u64;
                carry = cur >> 64;
                idx += 1;
            }
            i += 1;
        }
        r.len = (self.len + other.len).min(LIMBS);
        r.normalize();
        r
    }

    /// Long division: returns `(quotient, remainder)` with `self = q*m + r` and
    /// `0 <= r < m`. Panic-free: if `m` is zero, returns `(zero, self)`.
    ///
    /// Uses Knuth Algorithm D (divisor normalized so its top limb has its MSB
    /// set; 3-limb q-hat estimate with the add-back correction; remainder
    /// denormalized at the end). A single-limb divisor takes a fast path.
    pub fn divrem(&self, m: &Big) -> (Big, Big) {
        if m.is_zero() {
            return (zero(), *self);
        }
        if self.cmp(m) == Ordering::Less {
            return (zero(), *self);
        }

        // Single-limb divisor fast path.
        if m.len == 1 {
            let d = m.limbs[0] as u128;
            let mut q = zero();
            let mut rem = 0u128;
            let mut i = self.len;
            while i > 0 {
                i -= 1;
                let cur = (rem << 64) | (self.limbs[i] as u128);
                q.limbs[i] = (cur / d) as u64;
                rem = cur % d;
            }
            q.len = self.len;
            q.normalize();
            let mut r = zero();
            if rem != 0 {
                r.limbs[0] = rem as u64;
                r.len = 1;
            }
            return (q, r);
        }

        let n = m.len;
        let m_len = self.len;
        let b = 1u128 << 64;
        let shift = m.limbs[n - 1].leading_zeros();

        // Normalized divisor vn[0..n].
        let mut vn = [0u64; LIMBS];
        if shift == 0 {
            let mut i = 0;
            while i < n {
                vn[i] = m.limbs[i];
                i += 1;
            }
        } else {
            let mut i = n - 1;
            while i >= 1 {
                vn[i] = (m.limbs[i] << shift) | (m.limbs[i - 1] >> (64 - shift));
                i -= 1;
            }
            vn[0] = m.limbs[0] << shift;
        }

        // Normalized dividend un[0..=m_len].
        let mut un = [0u64; LIMBS + 1];
        if shift == 0 {
            let mut i = 0;
            while i < m_len {
                un[i] = self.limbs[i];
                i += 1;
            }
            un[m_len] = 0;
        } else {
            un[m_len] = self.limbs[m_len - 1] >> (64 - shift);
            let mut i = m_len - 1;
            while i >= 1 {
                un[i] = (self.limbs[i] << shift) | (self.limbs[i - 1] >> (64 - shift));
                i -= 1;
            }
            un[0] = self.limbs[0] << shift;
        }

        let mut q = zero();
        let mut j = (m_len - n) as isize;
        while j >= 0 {
            let ju = j as usize;
            let num = ((un[ju + n] as u128) << 64) | (un[ju + n - 1] as u128);
            let mut qhat = num / (vn[n - 1] as u128);
            let mut rhat = num % (vn[n - 1] as u128);
            loop {
                if qhat >= b
                    || qhat * (vn[n - 2] as u128) > (rhat << 64) | (un[ju + n - 2] as u128)
                {
                    qhat -= 1;
                    rhat += vn[n - 1] as u128;
                    if rhat < b {
                        continue;
                    }
                }
                break;
            }

            // Multiply and subtract qhat * vn from un[ju..=ju+n].
            let mut k: i128 = 0;
            let mut i = 0;
            while i < n {
                let p = qhat * (vn[i] as u128);
                let sub = (un[ju + i] as i128) + k - ((p as u64) as i128);
                un[ju + i] = sub as u64;
                k = (sub >> 64) - ((p >> 64) as i128);
                i += 1;
            }
            let t = (un[ju + n] as i128) + k;
            un[ju + n] = t as u64;

            if t < 0 {
                // qhat was one too large: add the divisor back.
                qhat -= 1;
                let mut c = 0u128;
                let mut i = 0;
                while i < n {
                    let s = (un[ju + i] as u128) + (vn[i] as u128) + c;
                    un[ju + i] = s as u64;
                    c = s >> 64;
                    i += 1;
                }
                un[ju + n] = ((un[ju + n] as u128) + c) as u64;
            }
            q.limbs[ju] = qhat as u64;
            j -= 1;
        }
        q.len = m_len - n + 1;
        q.normalize();

        // Denormalize the remainder (n limbs, shifted back down).
        let mut r = zero();
        if shift == 0 {
            let mut i = 0;
            while i < n {
                r.limbs[i] = un[i];
                i += 1;
            }
        } else {
            let mut i = 0;
            while i < n - 1 {
                r.limbs[i] = (un[i] >> shift) | (un[i + 1] << (64 - shift));
                i += 1;
            }
            r.limbs[n - 1] = un[n - 1] >> shift;
        }
        r.len = n;
        r.normalize();
        (q, r)
    }

    pub fn rem(&self, m: &Big) -> Big {
        self.divrem(m).1
    }

    pub fn addmod(&self, other: &Big, m: &Big) -> Big {
        self.add(other).rem(m)
    }

    pub fn submod(&self, other: &Big, m: &Big) -> Big {
        let a = self.rem(m);
        let b = other.rem(m);
        if a.cmp(&b) == Ordering::Less {
            a.add(m).sub(&b)
        } else {
            a.sub(&b)
        }
    }

    pub fn mulmod(&self, other: &Big, m: &Big) -> Big {
        self.mul(other).rem(m)
    }

    /// `self^exp mod m`, left-to-right square-and-multiply.
    pub fn modexp(&self, exp: &Big, m: &Big) -> Big {
        if m.is_zero() {
            return zero();
        }
        let one = from_u64(1);
        if m.cmp(&one) == Ordering::Equal {
            return zero();
        }
        let base = self.rem(m);
        let mut result = one;
        let mut i = exp.bit_len();
        while i > 0 {
            i -= 1;
            result = result.mulmod(&result, m);
            if exp.bit(i) {
                result = result.mulmod(&base, m);
            }
        }
        result
    }

    /// Modular inverse of `self` mod `m` via the extended Euclidean algorithm,
    /// carrying the Bezout coefficient reduced mod `m` (so all intermediates
    /// stay non-negative). Returns `None` if `gcd(self, m) != 1`.
    pub fn modinv(&self, m: &Big) -> Option<Big> {
        let one = from_u64(1);
        if m.cmp(&one) != Ordering::Greater {
            return None;
        }
        let a = self.rem(m);
        if a.is_zero() {
            return None;
        }
        let mut r0 = *m;
        let mut r1 = a;
        let mut t0 = zero();
        let mut t1 = one;
        while !r1.is_zero() {
            let (q, r2) = r0.divrem(&r1);
            let qt1 = q.mulmod(&t1, m);
            let t2 = t0.submod(&qt1, m);
            r0 = r1;
            r1 = r2;
            t0 = t1;
            t1 = t2;
        }
        if r0.cmp(&from_u64(1)) != Ordering::Equal {
            return None;
        }
        Some(t0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Big {
        let s = s.trim();
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut bytes = Vec::new();
        let padded;
        let s = if s.len() % 2 == 1 {
            padded = format!("0{s}");
            padded.as_str()
        } else {
            s
        };
        let mut i = 0;
        while i < s.len() {
            bytes.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
            i += 2;
        }
        from_be_bytes(&bytes)
    }

    fn hex_of(b: &Big, nbytes: usize) -> String {
        let mut out = vec![0u8; nbytes];
        b.to_be_bytes(&mut out);
        // strip leading zero bytes
        let mut start = 0;
        while start < out.len() - 1 && out[start] == 0 {
            start += 1;
        }
        let mut s = String::new();
        for byte in &out[start..] {
            s.push_str(&format!("{byte:02x}"));
        }
        // strip a single leading zero nibble
        if s.len() > 1 && s.starts_with('0') {
            s = s.trim_start_matches('0').to_string();
            if s.is_empty() {
                s.push('0');
            }
        }
        s
    }

    fn eq(a: &Big, b: &Big) -> bool {
        a.cmp(b) == Ordering::Equal
    }

    #[test]
    fn test_add_sub_mul_crossing_limbs() {
        let a = hx("deadbeefcafebabe0123456789abcdef");
        let b = hx("fedcba9876543210ffffffffffffffff");
        assert!(eq(&a.add(&b), &hx("01dd8a79884152eccf0123456789abcdee")));
        assert!(eq(&b.sub(&a), &hx("202efba8ab557752fedcba9876543210")));
        assert!(eq(
            &a.mul(&b),
            &hx("ddb06310dc4c1aa0826b700bc33359df44ac5f07a40ea020fedcba9876543211")
        ));
        assert!(a.checked_sub(&b).is_none());

        let x = hx("f59cde66bacfb3d00b1f9163ce9ff57f43b7a3a69a8dca03580d7b71d8f564135be6128e18c267976142ea7d17be31111a2a73ed562b0f79c37459eef50bea63371ecd7b27cd813047229389571aa8766c307511b2b9437a28df6ec4ce4a2bbdc241330b01a9e71fde8a774bcf36d58b4737819096da1dac72ff5d2a386ecbe06b65a6a48b8148f6b38a088ca65ed389b74d0fb132e706298fadc1a606cb0fb39a1de644815ef6d13b8faa1837f8a88b17fc695a07a0ca6e0822e8f36c031199972a846916419f828b9d2434e465e150bd9c66b3ad3c2d6d1a3d1fa7bc8960a923b8c1e9392456de3eb13b9046685257bdd640fb06671ad11c80317fa3b1799d");
        let y = hx("d304317faf42e12f3838b3268e944239b02b61c4a3d70628ece66fa2fd5166e6451b4cf36123fdf77656af7229d4beef3eabedcbbaa80dd488bd64072bcfbe01a28defe39bf0027312476f57a5e5a5abaefcfad8efc89849b3aa7efe4458a885ab9099a435a240ae5af305535ec42e0829a3b2e95d65a441d58842dea2bc372f7412b29347294739614ff3d719db3ad0ddd1dfb23b982ef8daf61a26146d3f31fc377a4c4a15544dc5e7ce8a3a578a8ea9488d990bbb259911ce5dd2b45ed1f03139d32c93cd59bf5c941cf0dc98d2c1e2acf72f9e574f7aa0ee89aed453dd324b0dbb418d5288f1142c3fe860e7a113ec1b8ca1f91e1d4c1ff49b7889463e85");
        let prod = hx("ca74513fad1e81b17446330751b002a28081c71c5f550053d2a55b14d157a9abd8afae35f8647a1a1b31d57ee00701eca3ae08e6a01592bf7ec2919d7495a631db8a7f66887e707713a69247455431498432853638f482db3a5ba804d02192ba1ab594196c64bda04d05b579fb1daf916b62e5c8cc245b838b50b9707aa99bf7ca7582abe246961a3f1a8c3e50da7e446e6e1823de7abb3dd023ab85ca4615cb38a680008402bd09e4d6e2f0ec5bd9739333ee5d68d851d3e306de3bf988c912eef132544ce5732d56f96de1b0952f194e37c3e12643907036f24df81d785cde23827dbaa1a64d66c7778fa0ca65c447f862344fc5fcb44e7ccc138a2db80dc684ff27a3ad36488638af121a3e2a52ee7dd6a927441a3501cf5aba378a81fae01e37b8aff8000d38ea049125dcb41931b3ac7087cac2aab15bb816a9f1dce657bef3227f5a58e4d7aa9aaf0306e0e34ea8f50a8a1b4549cbeaaae5d835d0dfdf5912ac3b09ffa6f414fcb2630946edadd5153f6e9adf464a3ab94a282b4b6c0c27c7c8e6490c0226423afd4bcc3c0664615a232358b24a1c3a4f410e3888691aa91c663e3d4a400f765ac6d634e620e8ad94a9b44e253f0e03106461952c25ddd835d56ad75c6372b3a838f794e5446da23eb2451f485ca70427617d788facecb9c7d05041414fec2468ccdcc4c9e1bc6df6a739cee4db84ce8e6e294c963491");
        assert!(eq(&x.mul(&y), &prod));
    }

    #[test]
    fn test_divrem_rem() {
        let d = hx("61b162801c4510435a1098ae43346c12ace8ae340454cac5b68c28f49481a0a04dc427209bdf1c11f735dc713d960c0fd195c17af08a1745d6d87e570ddf827050a82369b584ff5e9ff0ff50bde4382567b85cabcc97663f1c97956269f0e5d7b8756dadd6c795a76d79bf3c4c06434308bc89fa6a688fb5d27bbeb799193f22faf823bed01d43cf2fde24933b83757750a9a491f0b2ea1fca65e27a984d654821d07fcd9eb1a7cad415366eb16f508ebad7b7c93acfe059a0ee9132b63ef16287e4e9c349e03602f8ac10f1bc81448aaa9e66b2bc5b50c187fcce177b4e0837b8a3d261a7ab3aa2e4f90e51f30dc6a7ee39c4b032ccd7c524a5");
        let m = hx("dc5c0eed8da0365bf89897b9405cacec877409a977d21e02ff01cf99988c24c9");
        let (q, r) = d.divrem(&m);
        assert!(eq(&q, &hx("717e56aac07c2a2bb7ce9b64848cbebdaeaab3ef4b07e2da68666f45c7d1eba13874fb1254c720f16604b168d24a1b7c53fa7f8cc4db0b8a327cfbacab458861bf93014f670f4ec1a636133fb95d0b9f267003fde493a596237d9ef4497fe214b20599cd2738c51eae2bc1c6742ee0a20031e223c21f5143a3d0936328c53d1a6382566f5a651cfc3c214d46076d16fec28fd1a48996d33b4afb67d98ffead273e66f004fe10d15f24c8380d3917866a7ef767ed4e75a86095e3102c372cbcf9cdfe6a24569233f7ad9ea99270b0dcddf4984b40306d00e3938f")));
        assert!(eq(&r, &hx("12a35e2e62f90d581a7f3f540a649ed4306c5b881fd1855be3746b8e8a222d5e")));
        assert!(eq(&d.rem(&m), &r));

        // 4096-bit dividend mod 4096-bit modulus.
        let d2 = hx("e7c99b26114125c63a9bedd40f1259e0a18ff6b6b535106e122c9a5601d7425638602ab696a402f23ae8cc938dcdcd03969b666205628059568cc69b1064005c3985c3cf3f76be1d1efa21977394988f847fd9b4e64d1bcb702753a15f987c71a65e688eabf3ad39fec21bbe66245bfa4fcca39ab683d2e6337ea2dfb09b2a5cbadcc32ac1590f538a0f4efbedcd465e36386821f6e07cc06c52c49f9b49bd26df57c59a8715a10343dac0432a45c2ab8cbfedb0f264accc79ac1b1ea8e56e0c20de435d2031d750c40db9b4885f6e66c2b6d2c5fa5d310011b7e948d0e6e6607c69dee1bb5e4bcf15ed626914296c07f26b4776913e4de2e0c53cb83da9c2a90ed42f1a3d4cbf374eb93effce88cb2dd4e80839fc3e058be0f3eab05cec4eb5edd968311ca35cfb04fc6d827d15438552fbe43b99546eb400257ad1eb2263dd87c5421eec24a3c5c754108ff4188f3f8a14be62295b4715c333e8615fb8d16c2720797d32ebd6899be578c781f631d4a39231a7d777a4774c66e0a8a013ac6ededa4e161b3dbd5ce9a1fa6f81f76d1c2dbc2134c30ff46e8026695ff8cda88b436d76e2b83cfe0be037e5edb8db0672f42d47cc00d4af5974273ca3287d06ca6f4cc69a4b22d3081c8eaee95715bd6fa4161293c4c2e2e3444ea7c8c03987108976e334e2817efdae8492171d53434bb88139b9ae270da702f06b90f143262f");
        let m2 = hx("da4bd9caeb5cf46780bacd647a0ecfea958ca9ba0cd620c20ea2622b504867babf7b539b0f9aea4b8acd4e10bc594585944528c00ef8c2d6f7fd564637bb3eec4bf50b52309d258c27a0c3d77c967f79b7e99acaa97065e18e46d534c88a618efed4057dbb026576f512c4c3b253d2186c4a37ea490617f2747b6dbac8fe3ccdc8b8d9c6ed3049cf43e458fc63f2ae24fc3d3348008d4127610461e32a25a8880f02bad0e7067ef466aa9385dd59ba7136b824817b3a4e3e7c52fa17680ac07a2a935d623c835dc0d9441fa5c0e9ab30ed2662e917e011b7f810238303c72ba8d605e7708a63f881ffd0f9d5a6f2f7b80cf35b5819108be58ce21ea3db20a56edc815fe7ceda8bbb71710434134c6c92ec5b227cdfde4fbf3ff350bf766ecb15474ebc192ef912766c006f6123e2fcb472d8567d894a05e430b187ef310c0c003fa7f1041bf90e27dc96925eccf3a17156dc8907ba6c34ab6712303a0f844fef1931e9eea56c0941fbf24050a748dbcfac619e630dde29a6baa4b71add2467ac778eedb3693dffbc6c6fa6115ab33edf6e595ed3a8b317fa18d0752b1825bc5430beb45f683514f2ceb81f9d7914c120c8dcd19f3e3511287900f7f993829b43922fe15ae1e3db63ef7ddc76b92da22b21df306f8a0b3c3336d8393a7c441fe7ab4220a7474a493b3ceddf2d839fbc501223b5135496f63cdc1110c1080aadfb");
        let (q2, r2) = d2.divrem(&m2);
        assert!(eq(&q2, &hx("01")));
        assert!(eq(&r2, &hx("0d7dc15b25e4315eb9e1206f950389f60c034cfca85eefac038a382ab18eda9b78e4d71b870918a6b01b7e82d174877e02563da1f669bd825e8f7054d8a8c16fed90b87d0ed99890f7595dbff6fe1915cc963eea3cdcb5e9e1e07e6c970e1ae2a78a6310f0f147c309af56fab3d089e1e3826bb06d7dbaf3bf033524e79ced8ef223e963d428c584462af5ff89da983939fb34d9f6533b990b4e62bc7124149ed0550ac9a00f220edd302cbd4cec083a5607c92f772a5e8dfd59210740daad91f64ae5fae3ae798feac99a0ec775c335d5906fdce27d1f4819a7c5c5cd1fbab7a663f77130fa534d161c68936d36744fe577ec1e782dc1fd53e31e1462891d3a3252cf326e72337bdd483acbbb3c5e9ae88ce5bd1c5fb5cca10099f0e67d83a0a68aac17edaa4a8498fbfe21593246d0e0238dbe100a68cfcf73f2e2ba1657dd481d511ad02b959deabd7e312724edce3338355a6eef126a5c21b8275034817d0dee8f8e8d7fcd479ff33876daad5604f7309344c9997ad091c2298dc2ef44c2674b6062b1ffbda07d32545e27442e3cbf62c2611a5cdc746755f434e0a7ec3712aec2835007e919117fc6503fc645522b50762cc29f9e30fb2644a994fa6b86dd1ce53f693ef7a42d10d2729de81b448236e2243ab7a6b00d766e8e43f56728de34c28d9b3735c27196b2e999b386fba65d84a65990176a26df5acfe9387834")));

        // Exact multiple: remainder 0.
        let ed = hx("013026b327c6a7e9aba1b9fe3598e32e5a59e6e3999a9061521cc58c1f8f1ea97b4b27a87a0ee69469f8d1860eaf5b199841a3160ca03702ba641030dfb2932a07b5c987d8c8b831a7fa7813dfb73f25c7a30b09ef0719c830d804211b7e49");
        let em = hx("9e8fc9650a2c827e9832685694340a033f07f81491d63f78e3e9de99f10c718b");
        let (eq_, er) = ed.divrem(&em);
        assert!(er.is_zero());
        assert!(eq(&eq_, &hx("01eb0e675dd5af3c365296dca02eecacdabacc1165e21098543881118a9d292f923996d9f195d014822f5382010c62f5f59b220e8fa8e0284d82e587f7e1fb")));

        // Dividend < divisor: quotient 0, remainder = dividend.
        let ld = hx("4f47e4b28516413f4c19342b4a1a05019f83fc0a48eb1fbc71f4ef4cf88638c5");
        let lm = hx("9e8fc9650a2c827e9832685694340a033f07f81491d63f78e3e9de99f10c718b");
        let (lq, lr) = ld.divrem(&lm);
        assert!(lq.is_zero());
        assert!(eq(&lr, &ld));
    }

    #[test]
    fn test_modexp() {
        // 3^17 mod 1000000007
        let r = from_u64(3).modexp(&from_u64(17), &from_u64(1000000007));
        assert!(eq(&r, &from_u64(129140163)));

        // RSA-shaped: base^65537 mod n.
        let base = hx("951f58d05e84f058d5a804eb093923de8babce3b26286bfbe767dceab0e6a969e21342b0f1eedba313432e611ca3c4480279b6a68f9797b06d7ce3c9b4a69f3c8d3aed99711c21c9bdc14f1f295d6fbf430f801dfad409e2a319dcb4217d65a0c56811cd5563f61600e85ece0b49452d46d483f3d450281c6c6f7633a260772317a0df490d01280fd89a40c0e87d1c78e7c421c740497b717d106c6081627cf1439472e6da587e8aa25d6b29afffcfd2341ef40b57c700aab7b56ea735ebd32d9ad620ab48212ddb45b89cd927cb6f2a8da01097be0f051b1b66b5a9e3c436571d8cbbac43b409ef2260e70fe0ccedc5f05db76e1a84a51aa9d3d7c7ee87905e");
        let n = hx("cca415ea8dfa6a56d12dbc9aaaf915310200b1f08768a84fa76afde6ce9e1a11fcbb4e59fbddcf7c9c96e9ec4d71c366b41b31438b10550cd5704f32702cdd20286218b848f4ef125e9953d23e896c64e117dac3119c4ea3e18050815958a499eeea163e21e8ac6843e42caf8181a8cc369147eb89a2688b12c136e019985f15ff002d4d902059e4ff9ab5c29f044aed7552332702627f7312922f83ef8c485bc07a30f2edd4253b50f0fd0a750cab754ccc9bc2a53f8a28abf3e3fc21813d25655238a643ff50113d1a85dd506e5a9ab758588dab73295b344a54b842c18a62ef48e8d550fd9d3f85d5169590b2b633956b8c0ca8499b926b5252e314fcdd55");
        let expect = hx("87d47f859e2816584c1a567d5ad3541a41cc924c6081abd4cfb63ccc270dc41a529d37ec4a014ec459424c8b34960501ecdc3739284a21dc8736c76ec43fe3a034af4518a52349a40e73686c9007f94799ad0d3d267bb4b03b0202066c8856be3a5bf8be241af86752d6a75c80e14343b19afc3c8602fca6e1800665454b0edb4e3353e270494bcf897f5f06c2db61a99230a5df44a6039de7fd85a4105c0f66e96254884f2ffa3e2b7e1a31eb40e9a3565c9bb22794de76dbe26ef523645d3498cde672869b20073d60786625fc7aea53bd39f8bcb59f7fa907c5d98c9f4d863ed2ea050658984f0a122dd42afc8a2624e13349f9d2559c18f930548b572239");
        assert!(eq(&base.modexp(&from_u64(65537), &n), &expect));

        // 2^255 mod the P-256 prime.
        let p = hx("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        let r2 = from_u64(2).modexp(&hx("ff"), &p);
        assert!(eq(
            &r2,
            &hx("8000000000000000000000000000000000000000000000000000000000000000")
        ));
    }

    #[test]
    fn test_modinv() {
        // P-256 group order.
        let n = hx("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let s = hx("e623a6895d59cd2a4eea04e70ab54bde20a045026e06809725e979778d7248e3");
        let w = s.modinv(&n).unwrap();
        assert!(eq(&w, &hx("8bfc21d01776e411a18a0488025c6ac2db4d819201b59e9234bf7c2da18183fd")));
        assert!(eq(&s.mulmod(&w, &n), &from_u64(1)));

        // Small case.
        assert!(eq(&from_u64(3).modinv(&from_u64(11)).unwrap(), &from_u64(4)));

        // Non-invertible: gcd(6,9) = 3.
        assert!(from_u64(6).modinv(&from_u64(9)).is_none());
    }

    #[test]
    fn test_roundtrip_bytes() {
        let s32 = "35c7936c5b9962c6e61fecc00a368ce7dc570131f8e1daa7cbceabdeeededb07";
        let v32 = hx(s32);
        let mut out32 = [0u8; 32];
        v32.to_be_bytes(&mut out32);
        assert!(eq(&from_be_bytes(&out32), &v32));
        assert_eq!(hex_of(&v32, 32), s32);

        let s512 = "11e9cdaa6e6981a35d3d9e563270e4faabae4f43bcae8081bdf070aaf0b5156bb82c9074afd5dea589d7fd6cce777f00ecf27e7685197ff4006ed6e36fa17735b572f3d00b5cea6a41357e8c30a900ad939b462de645f129629c2ae31d9af65982ec9f2dfbf6e16f9b3080d56fb78271504d281fc9535b63ba81edd9587ef3446f3f920c98b8e4cc1bc044fc09cb394243f59a85fbc9f87af668a61794a1875d2db69edb42deffccf86c2ca2e08596db1d8709660710d430f071d87954c63cd889456f27d7fa2d8dfb2ca025adf4e62d6651529e8268690ba43825b559e4b6714774bc58c5f8bc16f7860b5011c58ef0dd463c09475287aa5408f9ac6601ddd03170f437a8f7ef5a060edf5b391184973a43b2badf0f06cbcb9bc326d20eac174e20fd1a598336e375d66ed4eb1fa9f2d10bd1d03317347038f16a81787f2425dbccc47709e9db0adf46529061ee411a1bac27a7b386f7a4c991603f28c13091444d610b3f87e362cf8d446abc2cbb0ddd334cc7ab7f089acd5f4822696608aaee49f329c84a7b28550a1b46ecab3301bc8f7d292dea94930658663a698c206fe1a47e102d534dd0cf8ebc5accc56569f9e8a3692999b735dd56cc943c9ad14cee0caeb5ecfedb992790cebdbfddc3d99ee3ac2af94d62046808593fdfed2c43e256a6dc8f5486b7c7b5b2bc5a8aaeca1a50aec3aabc25fa3fe12e47ae9bec36";
        let v512 = hx(s512);
        let mut out512 = [0u8; 512];
        v512.to_be_bytes(&mut out512);
        assert!(eq(&from_be_bytes(&out512), &v512));
        assert_eq!(hex_of(&v512, 512), s512);
    }

    #[test]
    fn test_misc() {
        assert!(zero().is_zero());
        assert_eq!(from_u64(0).bit_len(), 0);
        assert_eq!(from_u64(1).bit_len(), 1);
        assert_eq!(from_u64(0xffffffffffffffff).bit_len(), 64);
        assert!(from_u64(4).is_even());
        assert!(!from_u64(5).is_even());
        assert!(zero().is_even());
        // over-long input truncates to low LIMBS*8 bytes.
        let big = vec![0xffu8; LIMBS * 8 + 16];
        let t = from_be_bytes(&big);
        assert_eq!(t.bit_len(), LIMBS * 64);
    }
}
