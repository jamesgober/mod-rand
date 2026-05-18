//! Integration tests for the collection operations added in 1.0:
//! `shuffle`, `sample`, `weighted_index`, and `weighted_choice`.
//!
//! These tests verify distributional correctness — every output the
//! API claims is reachable must actually appear over a sufficiently
//! large sample, and the empirical distribution must approximate the
//! claimed distribution within chi-squared tolerance.

#![cfg(feature = "tier3")]

use mod_rand::tier1::Xoshiro256;
use mod_rand::tier3;

// ------------------------------------------------------------
// Shuffle
// ------------------------------------------------------------

#[test]
fn shuffle_preserves_multiset() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    let mut v: Vec<i32> = (0..1000).collect();
    let original_sum: i64 = v.iter().map(|&x| x as i64).sum();
    rng.shuffle(&mut v);
    let after_sum: i64 = v.iter().map(|&x| x as i64).sum();
    assert_eq!(original_sum, after_sum);
    // The set of values is unchanged.
    let mut sorted = v.clone();
    sorted.sort();
    let expected: Vec<i32> = (0..1000).collect();
    assert_eq!(sorted, expected);
}

#[test]
fn shuffle_actually_shuffles_long_slice() {
    let mut rng = Xoshiro256::seed_from_u64(2);
    let mut v: Vec<i32> = (0..1000).collect();
    let original = v.clone();
    rng.shuffle(&mut v);
    // Probability of returning the original permutation by chance is
    // 1 / 1000! — far below astronomical.
    assert_ne!(v, original);
}

#[test]
fn shuffle_empty_and_singleton_are_noops() {
    let mut rng = Xoshiro256::seed_from_u64(3);
    let mut empty: Vec<i32> = Vec::new();
    rng.shuffle(&mut empty);
    assert!(empty.is_empty());
    let mut singleton = vec![42];
    rng.shuffle(&mut singleton);
    assert_eq!(singleton, vec![42]);
}

#[test]
fn shuffle_permutation_distribution_is_uniform() {
    // 3-element slice: 6 permutations, expected count 10_000 each
    // over 60_000 shuffles. 5 d.f. chi-squared critical value at
    // alpha=0.001 is ~20.5; we cap at 50 to keep this stable.
    let mut rng = Xoshiro256::seed_from_u64(4);
    let mut perms = std::collections::HashMap::new();
    for _ in 0..60_000 {
        let mut v = [1u8, 2, 3];
        rng.shuffle(&mut v);
        *perms.entry(v).or_insert(0u32) += 1;
    }
    assert_eq!(perms.len(), 6, "expected all 6 permutations of [1,2,3]");
    let expected = 10_000.0;
    let chi: f64 = perms
        .values()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    assert!(chi < 50.0, "shuffle permutation chi-squared {chi} too high");
}

#[test]
fn tier3_shuffle_preserves_multiset() {
    let mut v: Vec<i32> = (0..256).collect();
    let original_sum: i64 = v.iter().map(|&x| x as i64).sum();
    tier3::shuffle(&mut v).unwrap();
    let after_sum: i64 = v.iter().map(|&x| x as i64).sum();
    assert_eq!(original_sum, after_sum);
}

#[test]
fn tier3_shuffle_actually_shuffles() {
    let mut v: Vec<i32> = (0..256).collect();
    let original = v.clone();
    tier3::shuffle(&mut v).unwrap();
    assert_ne!(v, original);
}

// ------------------------------------------------------------
// Sample
// ------------------------------------------------------------

#[test]
fn sample_returns_exactly_k_elements() {
    let mut rng = Xoshiro256::seed_from_u64(10);
    let pool: Vec<i32> = (0..100).collect();
    let picks = rng.sample(&pool, 17);
    assert_eq!(picks.len(), 17);
}

#[test]
fn sample_returns_distinct_elements_no_replacement() {
    // Distinct *references* into the slice mean distinct indices,
    // which (because the source is `0..100` injective) also means
    // distinct values.
    let mut rng = Xoshiro256::seed_from_u64(11);
    let pool: Vec<i32> = (0..100).collect();
    for _ in 0..1000 {
        let picks = rng.sample(&pool, 20);
        assert_eq!(picks.len(), 20);
        let mut values: Vec<i32> = picks.iter().map(|&&x| x).collect();
        values.sort();
        values.dedup();
        assert_eq!(values.len(), 20, "sample returned duplicates");
    }
}

#[test]
fn sample_k_equals_n_returns_all_elements_in_order() {
    let mut rng = Xoshiro256::seed_from_u64(12);
    let pool: Vec<i32> = (0..50).collect();
    let picks = rng.sample(&pool, 50);
    let collected: Vec<i32> = picks.iter().map(|&&x| x).collect();
    assert_eq!(collected, pool);
}

#[test]
fn sample_k_zero_returns_empty() {
    let mut rng = Xoshiro256::seed_from_u64(13);
    let pool: Vec<i32> = (0..50).collect();
    let picks = rng.sample(&pool, 0);
    assert!(picks.is_empty());
}

#[test]
fn sample_preserves_slice_order() {
    // Selection sampling returns references in original-slice order.
    let mut rng = Xoshiro256::seed_from_u64(14);
    let pool: Vec<i32> = (0..1000).collect();
    let picks = rng.sample(&pool, 50);
    let mut last = i32::MIN;
    for &&v in &picks {
        assert!(
            v > last,
            "sample output not in slice order: {v} after {last}"
        );
        last = v;
    }
}

#[test]
#[should_panic(expected = "exceeds slice length")]
fn sample_panics_when_k_greater_than_n() {
    let mut rng = Xoshiro256::seed_from_u64(15);
    let pool: Vec<i32> = (0..10).collect();
    let _ = rng.sample(&pool, 11);
}

#[test]
fn sample_uniformity_across_positions() {
    // For each position 0..N, count how often it is selected. With a
    // uniform sample of size k from a slice of size N, each position
    // should be selected k/N fraction of the time.
    let mut rng = Xoshiro256::seed_from_u64(16);
    const N: usize = 20;
    const K: usize = 5;
    const TRIALS: usize = 50_000;
    let pool: Vec<usize> = (0..N).collect();
    let mut counts = [0u32; N];
    for _ in 0..TRIALS {
        let picks = rng.sample(&pool, K);
        for &&v in &picks {
            counts[v] += 1;
        }
    }
    let expected = (TRIALS * K) as f64 / N as f64;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    // 19 d.f. chi-squared, alpha=0.001 ~ 43; cap at 80.
    assert!(chi < 80.0, "sample position chi-squared {chi} too high");
}

// ------------------------------------------------------------
// Weighted choice / weighted index
// ------------------------------------------------------------

#[test]
fn weighted_index_returns_some_for_nonzero_weights() {
    let mut rng = Xoshiro256::seed_from_u64(20);
    let weights = [1.0, 2.0, 3.0, 4.0];
    let i = rng.weighted_index(&weights).unwrap();
    assert!(i < 4);
}

#[test]
fn weighted_index_returns_none_for_empty_or_all_zero() {
    let mut rng = Xoshiro256::seed_from_u64(21);
    assert!(rng.weighted_index(&[]).is_none());
    assert!(rng.weighted_index(&[0.0, 0.0, 0.0]).is_none());
}

#[test]
fn weighted_index_distribution_matches_weights() {
    // Weights [1, 2, 3, 4] sum to 10. Expected fraction per bucket:
    // [10%, 20%, 30%, 40%]. Over 100_000 draws, chi-squared on
    // 3 d.f. at alpha=0.001 is ~16.3; cap at 40.
    let mut rng = Xoshiro256::seed_from_u64(22);
    let weights = [1.0, 2.0, 3.0, 4.0];
    let trials = 100_000;
    let mut counts = [0u32; 4];
    for _ in 0..trials {
        let i = rng.weighted_index(&weights).unwrap();
        counts[i] += 1;
    }
    let expected = [
        trials as f64 * 0.1,
        trials as f64 * 0.2,
        trials as f64 * 0.3,
        trials as f64 * 0.4,
    ];
    let chi: f64 = counts
        .iter()
        .zip(expected.iter())
        .map(|(&c, &e)| {
            let d = c as f64 - e;
            d * d / e
        })
        .sum();
    assert!(chi < 40.0, "weighted_index chi-squared {chi} too high");
}

#[test]
fn weighted_choice_returns_referenced_item() {
    let mut rng = Xoshiro256::seed_from_u64(23);
    let items = ["apple", "banana", "cherry"];
    let weights = [1.0, 1.0, 1.0];
    let pick = rng.weighted_choice(&items, &weights).unwrap();
    assert!(items.contains(pick));
}

#[test]
#[should_panic(expected = "items.len()")]
fn weighted_choice_panics_on_length_mismatch() {
    let mut rng = Xoshiro256::seed_from_u64(24);
    let items = ["a", "b", "c"];
    let weights = [1.0, 2.0];
    let _ = rng.weighted_choice(&items, &weights);
}

#[test]
#[should_panic(expected = "must be finite and non-negative")]
fn weighted_index_panics_on_negative() {
    let mut rng = Xoshiro256::seed_from_u64(25);
    let _ = rng.weighted_index(&[1.0, -2.0, 3.0]);
}

#[test]
#[should_panic(expected = "must be finite and non-negative")]
fn weighted_index_panics_on_nan() {
    let mut rng = Xoshiro256::seed_from_u64(26);
    let _ = rng.weighted_index(&[1.0, f64::NAN, 3.0]);
}

#[test]
#[should_panic(expected = "must be finite and non-negative")]
fn weighted_index_panics_on_infinity() {
    let mut rng = Xoshiro256::seed_from_u64(27);
    let _ = rng.weighted_index(&[1.0, f64::INFINITY, 3.0]);
}

#[test]
fn weighted_index_single_nonzero_bucket() {
    let mut rng = Xoshiro256::seed_from_u64(28);
    // Only one bucket has nonzero weight; every draw must land there.
    let weights = [0.0, 0.0, 1.0, 0.0];
    for _ in 0..1000 {
        assert_eq!(rng.weighted_index(&weights), Some(2));
    }
}
