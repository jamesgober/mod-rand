//! Tier 1 — deterministic PRNG for a Monte Carlo simulation.
//!
//! Estimate π by sampling uniformly in the unit square and counting
//! the fraction that fall inside the unit quarter-circle. The point
//! is to demonstrate a *reproducible* run: seed once, everyone with
//! the same seed sees the same number.
//!
//! Run with: `cargo run --release --example tier1_simulation`.

use mod_rand::tier1::Xoshiro256;

fn main() {
    let seed = 0x2026_0511_C0DE_F00D;
    let n: u64 = 10_000_000;

    let mut rng = Xoshiro256::seed_from_u64(seed);
    let mut inside = 0u64;
    for _ in 0..n {
        let x = rng.next_f64();
        let y = rng.next_f64();
        if x * x + y * y <= 1.0 {
            inside += 1;
        }
    }
    let pi_estimate = 4.0 * inside as f64 / n as f64;
    println!("seed     = {seed:#018x}");
    println!("samples  = {n}");
    println!("pi est.  = {pi_estimate:.6}");
    println!("error    = {:+.6}", pi_estimate - std::f64::consts::PI);
    println!();
    println!("Reproducibility: rerun this example and you'll get the");
    println!("same pi estimate to the last digit.");
}
