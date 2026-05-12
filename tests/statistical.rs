//! Statistical sanity tests for all three tiers.
//!
//! These are not a replacement for full BigCrush / TestU01 / Dieharder
//! coverage — they are sanity tests that surface gross algorithmic
//! breakage (state stuck, bit-bias, RNG returning constants). All
//! thresholds are deliberately loose; a passing run does not certify
//! cryptographic quality.
//!
//! Critical-value notes (chi-squared, upper-tail at α = 0.001):
//! - 15 d.f. → 37.7  (used here with cap 60)
//! - 31 d.f. → 61.1  (cap 100)
//! - 63 d.f. → 103   (cap 150)
//! - 255 d.f. → 330  (cap 500)
//!
//! Generous caps keep the false-failure rate well below 1-in-100-000
//! while still catching truly broken implementations.

mod common;

use common::{byte_frequency_chi_squared, runs_test_statistic};

mod tier1_stats {
    use super::*;
    use mod_rand::tier1::Xoshiro256;

    /// 1 048 576 raw bytes from Tier 1 should be uniformly distributed
    /// across 256 buckets.
    #[test]
    fn byte_frequency_passes_chi_squared() {
        let mut rng = Xoshiro256::seed_from_u64(0xC0FFEE);
        let mut buf = vec![0u8; 1 << 20];
        rng.fill_bytes(&mut buf);

        let chi = byte_frequency_chi_squared(&buf);
        assert!(chi < 500.0, "tier1 byte-frequency chi-squared = {chi}");
    }

    /// Runs test: count sign changes (compared with 0x80) — for an
    /// unbiased stream, the standardised statistic should fall within
    /// ±4σ with overwhelming probability.
    #[test]
    fn runs_test_within_bounds() {
        let mut rng = Xoshiro256::seed_from_u64(0x1234_5678);
        let mut buf = vec![0u8; 1 << 18];
        rng.fill_bytes(&mut buf);

        let z = runs_test_statistic(&buf);
        assert!(
            z.abs() < 6.0,
            "tier1 runs-test |z| = {} (>6σ implies stream is degenerate)",
            z.abs()
        );
    }

    /// Chi-squared on the bottom 8 bits of `next_u64` — these bits are
    /// the *weakest* in xoshiro256** (and still must pass a wide
    /// uniformity check).
    #[test]
    fn low_byte_of_u64_uniform() {
        let mut rng = Xoshiro256::seed_from_u64(7);
        let samples = 1_000_000;
        let mut counts = [0u32; 256];
        for _ in 0..samples {
            counts[(rng.next_u64() & 0xFF) as usize] += 1;
        }
        let n = samples as f64;
        let expected = n / 256.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 500.0, "low-byte chi-squared {chi}");
    }

    /// Chi-squared on the *top* 8 bits of `next_u64` — the strongest
    /// bits per the xoshiro authors.
    #[test]
    fn high_byte_of_u64_uniform() {
        let mut rng = Xoshiro256::seed_from_u64(13);
        let samples = 1_000_000;
        let mut counts = [0u32; 256];
        for _ in 0..samples {
            counts[(rng.next_u64() >> 56) as usize] += 1;
        }
        let n = samples as f64;
        let expected = n / 256.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 500.0, "high-byte chi-squared {chi}");
    }

    /// `jump` and a clone's normal `next_u64` should diverge: the two
    /// streams must not produce the same value at any of the first N
    /// outputs. A bug that left jump as a no-op would surface here.
    #[test]
    fn jump_produces_independent_stream() {
        let mut a = Xoshiro256::seed_from_u64(1);
        let mut b = a.clone();
        b.jump();
        // Compare 4096 outputs from each. A no-op jump means every
        // output coincides; a correct jump means coincidences happen
        // only at the chance rate 2^-64.
        let mut coincidences = 0;
        for _ in 0..4096 {
            if a.next_u64() == b.next_u64() {
                coincidences += 1;
            }
        }
        assert!(
            coincidences == 0,
            "jump_produces_independent_stream: {coincidences} unexpected matches"
        );
    }

    /// `long_jump` similarly produces an independent stream.
    #[test]
    fn long_jump_produces_independent_stream() {
        let mut a = Xoshiro256::seed_from_u64(1);
        let mut b = a.clone();
        b.long_jump();
        let mut coincidences = 0;
        for _ in 0..4096 {
            if a.next_u64() == b.next_u64() {
                coincidences += 1;
            }
        }
        assert!(coincidences == 0, "long_jump matches: {coincidences}");
    }

    /// `next_f64` must spread across (0,1) — bucket into deciles and
    /// chi-squared on the histogram.
    #[test]
    fn next_f64_uniform_over_unit_interval() {
        let mut rng = Xoshiro256::seed_from_u64(2026);
        let samples = 1_000_000;
        let mut buckets = [0u32; 10];
        for _ in 0..samples {
            let f = rng.next_f64();
            let idx = ((f * 10.0) as usize).min(9);
            buckets[idx] += 1;
        }
        let n = samples as f64;
        let expected = n / 10.0;
        let chi: f64 = buckets
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        // 9 d.f. critical value at α=0.001 is ~27.9; cap at 50.
        assert!(chi < 50.0, "next_f64 decile chi {chi}");
    }
}

#[cfg(feature = "tier2")]
mod tier2_stats {
    use mod_rand::tier2;
    use std::collections::HashSet;

    /// 1 000 000 calls must yield 1 000 000 distinct values — the
    /// counter guarantees this; any failure means the counter is being
    /// mixed away.
    #[test]
    fn one_million_unique_u64_distinct() {
        let n = 1_000_000;
        let mut set = HashSet::with_capacity(n);
        for _ in 0..n {
            assert!(set.insert(tier2::unique_u64()), "collision at scale");
        }
        assert_eq!(set.len(), n);
    }

    /// 1 000 000 base32 16-char names must all be distinct. 16 chars
    /// = 80 bits; birthday collisions at 1M draws expect about
    /// 1M^2 / 2^81 ≈ 4×10^-13 collisions — i.e., never in practice.
    #[test]
    fn one_million_unique_names_distinct() {
        let n = 1_000_000;
        let mut set = HashSet::with_capacity(n);
        for _ in 0..n {
            assert!(set.insert(tier2::unique_name(16)));
        }
    }

    /// Crockford alphabet usage must be roughly uniform across a large
    /// sample of single-char names.
    #[test]
    fn alphabet_distribution_uniform() {
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let samples = 200_000;
        let mut counts = [0u32; 32];
        for _ in 0..samples {
            let c = tier2::unique_base32(1).chars().next().unwrap();
            let idx = ALPHABET
                .iter()
                .position(|&b| b as char == c)
                .expect("Crockford char");
            counts[idx] += 1;
        }
        let n = samples as f64;
        let expected = n / 32.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 100.0, "tier2 base32 chi-squared {chi}");
    }
}

#[cfg(feature = "tier3")]
mod tier3_stats {
    use super::*;
    use mod_rand::tier3;

    /// 1 048 576 cryptographic bytes — chi-squared bucket test.
    #[test]
    fn byte_frequency_passes_chi_squared() {
        let buf = tier3::random_bytes(1 << 20).unwrap();
        let chi = byte_frequency_chi_squared(&buf);
        assert!(chi < 500.0, "tier3 byte-frequency chi-squared = {chi}");
    }

    /// Runs test on tier3 output.
    #[test]
    fn runs_test_within_bounds() {
        let buf = tier3::random_bytes(1 << 18).unwrap();
        let z = runs_test_statistic(&buf);
        assert!(z.abs() < 6.0, "tier3 runs-test |z| = {}", z.abs());
    }

    /// 10 000 calls of 32 bytes each — verifies syscall robustness
    /// over time.
    #[test]
    fn stress_ten_thousand_calls() {
        for _ in 0..10_000 {
            let mut buf = [0u8; 32];
            tier3::fill_bytes(&mut buf).unwrap();
        }
    }

    /// Sequential 16-byte tokens are pairwise distinct. 16 bytes is
    /// 128 bits — collisions are unobservable.
    #[test]
    fn tokens_are_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::with_capacity(10_000);
        for _ in 0..10_000 {
            assert!(set.insert(tier3::random_hex(16).unwrap()));
        }
    }
}
