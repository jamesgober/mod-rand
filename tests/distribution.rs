//! Integration tests for the Tier 1 distribution helpers added in 1.0:
//! `gen_f64`, `gen_f32`, and `gen_bool`.

use mod_rand::tier1::Xoshiro256;

#[test]
fn gen_f64_is_in_unit_interval() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    for _ in 0..50_000 {
        let f = rng.gen_f64();
        assert!((0.0..1.0).contains(&f));
    }
}

#[test]
fn gen_f64_alias_matches_next_f64_under_same_seed() {
    let mut a = Xoshiro256::seed_from_u64(2);
    let mut b = Xoshiro256::seed_from_u64(2);
    for _ in 0..1000 {
        assert_eq!(a.gen_f64(), b.next_f64());
    }
}

#[test]
fn gen_f32_is_in_unit_interval() {
    let mut rng = Xoshiro256::seed_from_u64(3);
    for _ in 0..50_000 {
        let f = rng.gen_f32();
        assert!((0.0_f32..1.0).contains(&f));
    }
}

#[test]
fn gen_f32_decile_uniformity() {
    // 100_000 draws over 10 deciles. Expected count per bucket:
    // 10_000. 9 d.f. chi-squared at alpha=0.001 ~ 27.9; cap at 60.
    let mut rng = Xoshiro256::seed_from_u64(4);
    let mut counts = [0u32; 10];
    for _ in 0..100_000 {
        let f = rng.gen_f32();
        let b = (f * 10.0) as usize;
        let b = b.min(9);
        counts[b] += 1;
    }
    let expected = 10_000.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    assert!(chi < 60.0, "gen_f32 decile chi-squared {chi} too high");
}

#[test]
fn gen_bool_endpoints() {
    let mut rng = Xoshiro256::seed_from_u64(5);
    // p = 0 always false; p = 1 always true.
    for _ in 0..1000 {
        assert!(!rng.gen_bool(0.0));
        assert!(rng.gen_bool(1.0));
    }
}

#[test]
fn gen_bool_p_one_half_is_balanced() {
    // 100_000 trials at p=0.5. Expected true count 50_000;
    // 1 d.f. chi-squared at alpha=0.001 ~ 10.8; cap at 30.
    let mut rng = Xoshiro256::seed_from_u64(6);
    let mut t = 0u32;
    let trials = 100_000u32;
    for _ in 0..trials {
        if rng.gen_bool(0.5) {
            t += 1;
        }
    }
    let f = trials - t;
    let expected = (trials as f64) / 2.0;
    let chi = {
        let dt = t as f64 - expected;
        let df = f as f64 - expected;
        dt * dt / expected + df * df / expected
    };
    assert!(chi < 30.0, "gen_bool(0.5) chi-squared {chi} too high");
}

#[test]
fn gen_bool_p_one_quarter_distribution() {
    // 100_000 trials at p=0.25. Expected true ratio 25%.
    // Same threshold reasoning as the half case.
    let mut rng = Xoshiro256::seed_from_u64(7);
    let mut t = 0u32;
    let trials = 100_000u32;
    for _ in 0..trials {
        if rng.gen_bool(0.25) {
            t += 1;
        }
    }
    let expected_t = (trials as f64) * 0.25;
    let expected_f = (trials as f64) * 0.75;
    let f = trials - t;
    let chi = {
        let dt = t as f64 - expected_t;
        let df = f as f64 - expected_f;
        dt * dt / expected_t + df * df / expected_f
    };
    assert!(chi < 30.0, "gen_bool(0.25) chi-squared {chi} too high");
}

#[test]
#[should_panic(expected = "must be finite and in")]
fn gen_bool_panics_on_negative_p() {
    let mut rng = Xoshiro256::seed_from_u64(8);
    let _ = rng.gen_bool(-0.01);
}

#[test]
#[should_panic(expected = "must be finite and in")]
fn gen_bool_panics_on_above_one_p() {
    let mut rng = Xoshiro256::seed_from_u64(9);
    let _ = rng.gen_bool(1.0001);
}

#[test]
#[should_panic(expected = "must be finite and in")]
fn gen_bool_panics_on_nan_p() {
    let mut rng = Xoshiro256::seed_from_u64(10);
    let _ = rng.gen_bool(f64::NAN);
}
