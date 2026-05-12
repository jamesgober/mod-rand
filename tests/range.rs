//! Integration tests for the bounded-range API across all three tiers.
//!
//! These tests verify the spec from `REPS.md` section 4 — uniformity,
//! invalid-range handling, and full-width edge cases — at a larger
//! scale than fits in unit tests.

#![cfg(all(feature = "tier2", feature = "tier3"))]

use mod_rand::tier1::Xoshiro256;
use mod_rand::{tier2, tier3};

// ------------------------------------------------------------
// Uniformity at scale
// ------------------------------------------------------------

/// 1,000,000-draw chi-squared test on Tier 1's `gen_range_u32`.
///
/// The reduction from 64-bit PRNG output to a small integer range is
/// where modulo bias would show up if the implementation were
/// incorrect. Lemire's rejection sampling makes the output uniform;
/// this test verifies that empirically.
///
/// Bucket count: 100. Expected count per bucket: 10,000.
/// Chi-squared critical value (99 d.f., alpha=0.0001): ~165.
/// We use 250 as the failure threshold to keep flake rate negligible.
#[test]
fn tier1_uniformity_1m_draws() {
    let mut rng = Xoshiro256::seed_from_u64(0xC0DE_F00D_2026);
    let mut counts = [0u64; 100];
    for _ in 0..1_000_000 {
        let v = rng.gen_range_u32(0..100);
        counts[v as usize] += 1;
    }
    let expected = 10_000.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();
    assert!(
        chi < 250.0,
        "tier1 1M-draw chi-squared {chi} too high — bias detected"
    );
}

/// 1,000,000-draw chi-squared test on Tier 2's `range_u32`.
///
/// Tier 2's `unique_u64` source is uniform-looking after Stafford
/// mixing; the bounded-range reduction must preserve that.
#[test]
fn tier2_uniformity_1m_draws() {
    let mut counts = [0u64; 100];
    for _ in 0..1_000_000 {
        let v = tier2::range_u32(0..100);
        counts[v as usize] += 1;
    }
    let expected = 10_000.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();
    assert!(
        chi < 250.0,
        "tier2 1M-draw chi-squared {chi} too high — bias detected"
    );
}

/// 50,000-draw chi-squared test on Tier 3.
///
/// Tier 3 is rate-limited by syscall overhead, so we test with fewer
/// draws than Tier 1/2. The OS CSPRNG is already statistically sound;
/// this test exists primarily to verify the rejection-sampling layer
/// doesn't introduce bias.
#[test]
fn tier3_uniformity_50k_draws() {
    let mut counts = [0u64; 50];
    for _ in 0..50_000 {
        let v = tier3::random_range_u32(0..50).expect("CSPRNG available");
        counts[v as usize] += 1;
    }
    let expected = 1000.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();
    assert!(
        chi < 200.0,
        "tier3 50k-draw chi-squared {chi} too high — bias detected"
    );
}

// ------------------------------------------------------------
// Die-roll uniformity (the canonical modulo-bias trap)
// ------------------------------------------------------------

/// Tier 1 six-sided die test. 600,000 rolls; each face should appear
/// ~100,000 times. This is the test that catches naive `% 6`
/// reduction, since 2^64 is not divisible by 6.
#[test]
fn tier1_die_roll_uniformity() {
    let mut rng = Xoshiro256::seed_from_u64(0xD1CE_2026);
    let mut faces = [0u64; 6];
    for _ in 0..600_000 {
        let d = rng.gen_range_inclusive_u32(1..=6);
        faces[(d - 1) as usize] += 1;
    }
    let expected = 100_000.0;
    let chi: f64 = faces
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();
    // 5 d.f., alpha=0.001 critical value ~21; cap at 50.
    assert!(chi < 50.0, "tier1 d6 chi-squared {chi} — bias detected");
}

// ------------------------------------------------------------
// Edge cases
// ------------------------------------------------------------

/// Spec: a single-value inclusive range `start..=start` returns
/// `start` (no rejection, no waste).
#[test]
fn single_value_inclusive_ranges_return_start_on_all_tiers() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    for v in [0u64, 1, 42, u64::MAX] {
        assert_eq!(rng.gen_range_inclusive_u64(v..=v), v);
        assert_eq!(tier2::range_inclusive_u64(v..=v), v);
        assert_eq!(tier3::random_range_inclusive_u64(v..=v).unwrap(), v);
    }
}

/// Spec: full-width inclusive ranges are supported on every tier.
#[test]
fn full_width_inclusive_ranges_supported() {
    let mut rng = Xoshiro256::seed_from_u64(2);
    let _ = rng.gen_range_inclusive_u64(0..=u64::MAX);
    let _ = rng.gen_range_inclusive_u32(0..=u32::MAX);
    let _ = rng.gen_range_inclusive_i64(i64::MIN..=i64::MAX);
    let _ = rng.gen_range_inclusive_i32(i32::MIN..=i32::MAX);

    let _ = tier2::range_inclusive_u64(0..=u64::MAX);
    let _ = tier2::range_inclusive_u32(0..=u32::MAX);
    let _ = tier2::range_inclusive_i64(i64::MIN..=i64::MAX);
    let _ = tier2::range_inclusive_i32(i32::MIN..=i32::MAX);

    tier3::random_range_inclusive_u64(0..=u64::MAX).unwrap();
    tier3::random_range_inclusive_u32(0..=u32::MAX).unwrap();
    tier3::random_range_inclusive_i64(i64::MIN..=i64::MAX).unwrap();
    tier3::random_range_inclusive_i32(i32::MIN..=i32::MAX).unwrap();
}

/// Spec: half-open `Range` never produces the upper bound. Tier 1 is
/// deterministic, so a sufficiently large sample size will produce
/// every interior value but never the bound.
#[test]
fn half_open_never_produces_upper_bound_tier1() {
    let mut rng = Xoshiro256::seed_from_u64(3);
    for _ in 0..100_000 {
        let v = rng.gen_range_u64(0..10);
        assert!(v < 10);
    }
}

/// Spec: inclusive `RangeInclusive` produces the upper bound with
/// non-negligible probability for a small range.
#[test]
fn inclusive_produces_upper_bound_tier1() {
    let mut rng = Xoshiro256::seed_from_u64(4);
    let mut saw_top = false;
    for _ in 0..10_000 {
        let v = rng.gen_range_inclusive_u64(0..=10);
        if v == 10 {
            saw_top = true;
            break;
        }
    }
    assert!(saw_top, "inclusive range never produced its upper bound");
}

// ------------------------------------------------------------
// Determinism — Tier 1 only
// ------------------------------------------------------------

/// Spec: replaying the same seed + same sequence of `gen_range_*`
/// calls MUST produce identical output. This is the core determinism
/// guarantee for Tier 1.
#[test]
fn tier1_bounded_range_is_deterministic() {
    let mut a = Xoshiro256::seed_from_u64(0xDEAD_BEEF);
    let mut b = Xoshiro256::seed_from_u64(0xDEAD_BEEF);
    for _ in 0..1000 {
        assert_eq!(a.gen_range_u64(0..1000), b.gen_range_u64(0..1000));
        assert_eq!(a.gen_range_i32(-100..100), b.gen_range_i32(-100..100));
        assert_eq!(
            a.gen_range_inclusive_u32(1..=6),
            b.gen_range_inclusive_u32(1..=6)
        );
        let af = a.gen_range_f64(-1.0..1.0);
        let bf = b.gen_range_f64(-1.0..1.0);
        assert!((af - bf).abs() < 1e-15);
    }
}
