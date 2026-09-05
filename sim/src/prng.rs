//! A deterministic seeded pseudo random number generator.
//!
//! This is a splitmix64 generator. It is not cryptographically secure and is
//! never used inside the kernel loop. It exists only to generate reproducible
//! random workloads so that a seed fully determines a run.

/// A small, fast, fully deterministic splitmix64 PRNG.
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    /// Create a generator from a seed. The same seed always yields the same
    /// sequence.
    pub fn new(seed: u64) -> Self {
        Prng { state: seed }
    }

    /// Return the next 64 bit value and advance the state.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Return a value in the half open range `[low, high)`.
    ///
    /// Panics if `low >= high`.
    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        assert!(low < high, "range requires low < high");
        low + self.next_u64() % (high - low)
    }

    /// Return a byte value.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_diverges() {
        let mut a = Prng::new(1);
        let mut b = Prng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn range_is_bounded() {
        let mut p = Prng::new(7);
        for _ in 0..10000 {
            let v = p.range(10, 20);
            assert!((10..20).contains(&v));
        }
    }
}
