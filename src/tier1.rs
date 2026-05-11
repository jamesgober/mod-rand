//! # Tier 1 — Fast deterministic PRNG
//!
//! Pseudorandom number generator suitable for simulation, test
//! fixtures, and non-security shuffling. Seedable so runs are
//! reproducible. **Not cryptographically secure** — outputs are
//! predictable given the seed.
//!
//! Default algorithm: xoshiro256\*\* (~1ns/u64 on modern hardware).

/// xoshiro256** PRNG.
///
/// Fast, statistically sound generator from the xoshiro family.
/// Produces 64-bit values. Seedable from a single u64.
///
/// # Example
///
/// ```
/// use mod_rand::tier1::Xoshiro256;
///
/// let mut rng = Xoshiro256::seed_from_u64(42);
/// let n: u64 = rng.next_u64();
/// ```
#[derive(Debug, Clone)]
pub struct Xoshiro256 {
    state: [u64; 4],
}

impl Xoshiro256 {
    /// Seed the generator from a single `u64`.
    ///
    /// In `0.1.0` this is a placeholder; the real splitmix64 seeding
    /// lands in `0.9.x`.
    pub fn seed_from_u64(seed: u64) -> Self {
        // Placeholder seeding. The real splitmix64-based seed
        // expansion lands in 0.9.x.
        let s = seed.max(1);
        Self {
            state: [s, s.wrapping_mul(2), s.wrapping_mul(3), s.wrapping_mul(5)],
        }
    }

    /// Produce the next `u64` in the sequence.
    ///
    /// In `0.1.0` this is a placeholder. The real xoshiro256\*\*
    /// algorithm lands in `0.9.x`.
    pub fn next_u64(&mut self) -> u64 {
        // Placeholder. Real xoshiro256** lands in 0.9.x.
        let result = self.state[0].wrapping_add(self.state[3]);
        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_produces_a_value() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.next_u64();
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut a = Xoshiro256::seed_from_u64(1);
        let mut b = Xoshiro256::seed_from_u64(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn same_seed_produces_same_stream() {
        let mut a = Xoshiro256::seed_from_u64(42);
        let mut b = Xoshiro256::seed_from_u64(42);
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
