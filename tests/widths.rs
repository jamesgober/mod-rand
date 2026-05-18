//! Integration tests for the additional integer widths added in 1.0.
//!
//! The 0.9.x line shipped bounded-range support for `u32`, `u64`, `i32`,
//! `i64` (and `f64`). 1.0 extends that to every primitive integer width
//! callers actually need: `u8`, `u16`, `u128`, `usize`, `i8`, `i16`,
//! `i128`, `isize`, both half-open and inclusive on every tier.
//!
//! These tests exercise the cross-cutting properties — boundary handling,
//! full-width inclusive ranges, sign handling, and 128-bit uniformity —
//! at integration scale rather than in unit tests.

#![cfg(all(feature = "tier2", feature = "tier3"))]

use mod_rand::tier1::Xoshiro256;
use mod_rand::{tier2, tier3};

// ------------------------------------------------------------
// Tier 1 — bounds + full-width edges across every width
// ------------------------------------------------------------

#[test]
fn tier1_u8_bounds_and_full_width() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    for _ in 0..10_000 {
        let n = rng.gen_range_u8(0..100);
        assert!(n < 100);
    }
    // Full-width inclusive: every byte value must be reachable.
    let mut seen = [false; 256];
    for _ in 0..50_000 {
        seen[rng.gen_range_inclusive_u8(0..=u8::MAX) as usize] = true;
    }
    assert!(
        seen.iter().filter(|s| **s).count() > 200,
        "0..=u8::MAX did not reach diverse byte values"
    );
}

#[test]
fn tier1_u16_bounds_and_full_width() {
    let mut rng = Xoshiro256::seed_from_u64(2);
    for _ in 0..10_000 {
        let n = rng.gen_range_u16(100..1000);
        assert!((100..1000).contains(&n));
    }
    for _ in 0..1000 {
        let _ = rng.gen_range_inclusive_u16(0..=u16::MAX);
    }
}

#[test]
fn tier1_u128_bounds() {
    let mut rng = Xoshiro256::seed_from_u64(3);
    let lo: u128 = 1_000_000_000_000;
    let hi: u128 = u128::MAX / 2;
    for _ in 0..1000 {
        let n = rng.gen_range_u128(lo..hi);
        assert!((lo..hi).contains(&n));
    }
}

#[test]
fn tier1_u128_full_width_inclusive() {
    // 0..=u128::MAX exercises the raw 128-bit-draw special case.
    let mut rng = Xoshiro256::seed_from_u64(4);
    let a = rng.gen_range_inclusive_u128(0..=u128::MAX);
    let b = rng.gen_range_inclusive_u128(0..=u128::MAX);
    assert_ne!(a, b, "two consecutive full-width u128 draws should differ");
}

#[test]
fn tier1_u128_uniformity_chi_squared() {
    // 100_000 draws over a u128 range divided into 100 buckets.
    // Threshold matches the existing tier1 chi-squared (~250).
    let mut rng = Xoshiro256::seed_from_u64(0x1_2345_6789);
    let bucket_count: u128 = 100;
    let mut counts = [0u32; 100];
    let span: u128 = 1_000_000;
    for _ in 0..100_000 {
        let v = rng.gen_range_u128(0..span);
        let b = (v * bucket_count / span) as usize;
        counts[b] += 1;
    }
    let expected = 1_000.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    assert!(chi < 250.0, "u128 bounded-range chi-squared {chi} too high");
}

#[test]
fn tier1_usize_bounds_and_full_width() {
    let mut rng = Xoshiro256::seed_from_u64(5);
    for _ in 0..10_000 {
        let n = rng.gen_range_usize(0..1000);
        assert!(n < 1000);
    }
    let _ = rng.gen_range_inclusive_usize(0..=usize::MAX);
}

#[test]
fn tier1_i8_negative_and_mixed_sign() {
    let mut rng = Xoshiro256::seed_from_u64(6);
    let mut saw_neg = false;
    let mut saw_pos = false;
    for _ in 0..10_000 {
        let n = rng.gen_range_i8(-100..50);
        assert!((-100..50).contains(&n));
        if n < 0 {
            saw_neg = true;
        } else {
            saw_pos = true;
        }
    }
    assert!(saw_neg && saw_pos);
    // Full-width inclusive.
    for _ in 0..1000 {
        let _ = rng.gen_range_inclusive_i8(i8::MIN..=i8::MAX);
    }
}

#[test]
fn tier1_i16_negative_and_mixed_sign() {
    let mut rng = Xoshiro256::seed_from_u64(7);
    for _ in 0..10_000 {
        let n = rng.gen_range_i16(-1000..1000);
        assert!((-1000..1000).contains(&n));
    }
    for _ in 0..1000 {
        let _ = rng.gen_range_inclusive_i16(i16::MIN..=i16::MAX);
    }
}

#[test]
fn tier1_i128_mixed_sign_and_full_width() {
    let mut rng = Xoshiro256::seed_from_u64(8);
    for _ in 0..1000 {
        let n = rng.gen_range_i128(-1_000_000..1_000_000);
        assert!((-1_000_000..1_000_000).contains(&n));
    }
    // Full-width inclusive — exercises the raw 128-bit reinterpret.
    let a = rng.gen_range_inclusive_i128(i128::MIN..=i128::MAX);
    let b = rng.gen_range_inclusive_i128(i128::MIN..=i128::MAX);
    assert_ne!(a, b, "two consecutive full-width i128 draws should differ");
}

#[test]
fn tier1_isize_bounds_and_full_width() {
    let mut rng = Xoshiro256::seed_from_u64(9);
    for _ in 0..10_000 {
        let n = rng.gen_range_isize(-1000..1000);
        assert!((-1000..1000).contains(&n));
    }
    let _ = rng.gen_range_inclusive_isize(isize::MIN..=isize::MAX);
}

// ------------------------------------------------------------
// Tier 2 — analogous spot-checks for the new widths
// ------------------------------------------------------------

#[test]
fn tier2_u8_u16_u128_bounds() {
    for _ in 0..1000 {
        assert!(tier2::range_u8(0..100) < 100);
        assert!(tier2::range_u16(0..1000) < 1000);
    }
    for _ in 0..200 {
        let n = tier2::range_u128(0..u128::MAX / 2);
        assert!(n < u128::MAX / 2);
    }
    // Full-width u128 inclusive.
    let a = tier2::range_inclusive_u128(0..=u128::MAX);
    let b = tier2::range_inclusive_u128(0..=u128::MAX);
    assert_ne!(a, b);
}

#[test]
fn tier2_i128_full_width() {
    let _ = tier2::range_inclusive_i128(i128::MIN..=i128::MAX);
}

#[test]
fn tier2_usize_isize_full_width() {
    let _ = tier2::range_inclusive_usize(0..=usize::MAX);
    let _ = tier2::range_inclusive_isize(isize::MIN..=isize::MAX);
}

#[test]
#[should_panic(expected = "empty range")]
fn tier2_range_u128_empty_panics() {
    let _ = tier2::range_u128(10..10);
}

// ------------------------------------------------------------
// Tier 3 — analogous spot-checks (fewer iterations: each draw is a syscall)
// ------------------------------------------------------------

#[test]
fn tier3_u8_u16_u128_bounds() {
    for _ in 0..200 {
        assert!(tier3::random_range_u8(0..100).unwrap() < 100);
        assert!(tier3::random_range_u16(0..1000).unwrap() < 1000);
    }
    for _ in 0..50 {
        let n = tier3::random_range_u128(0..u128::MAX / 2).unwrap();
        assert!(n < u128::MAX / 2);
    }
    let a = tier3::random_range_inclusive_u128(0..=u128::MAX).unwrap();
    let b = tier3::random_range_inclusive_u128(0..=u128::MAX).unwrap();
    assert_ne!(a, b);
}

#[test]
fn tier3_i128_full_width() {
    let _ = tier3::random_range_inclusive_i128(i128::MIN..=i128::MAX).unwrap();
}

#[test]
fn tier3_usize_isize_full_width() {
    let _ = tier3::random_range_inclusive_usize(0..=usize::MAX).unwrap();
    let _ = tier3::random_range_inclusive_isize(isize::MIN..=isize::MAX).unwrap();
}

#[test]
fn tier3_empty_range_returns_invalid_input() {
    let err = tier3::random_range_u128(10..10).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    let err = tier3::random_range_i128(0..0).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
