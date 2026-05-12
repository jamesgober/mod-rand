//! Bounded-range generation across all three tiers.
//!
//! Demonstrates the `..` (half-open) and `..=` (inclusive) range
//! syntax for each tier, including signed and unsigned variants.
//!
//! Run with: `cargo run --release --example bounded_ranges`.

use mod_rand::tier1::Xoshiro256;

fn main() {
    println!("=== Tier 1 — deterministic bounded ranges ===\n");

    let mut rng = Xoshiro256::seed_from_u64(0xC0DE_F00D);

    // Half-open range: [1, 100). Returns 1..99 inclusive in
    // value, never 100.
    println!("gen_range_u32(1..100)        — half-open");
    for _ in 0..5 {
        println!("  {}", rng.gen_range_u32(1..100));
    }

    // Inclusive range: [1, 100]. Can return 100.
    println!("\ngen_range_inclusive_u32(1..=100)  — inclusive");
    for _ in 0..5 {
        println!("  {}", rng.gen_range_inclusive_u32(1..=100));
    }

    // Classic dice mechanic: roll 3d6.
    println!("\n3d6 (three six-sided dice):");
    let dice: Vec<u32> = (0..3).map(|_| rng.gen_range_inclusive_u32(1..=6)).collect();
    let total: u32 = dice.iter().sum();
    println!("  {} + {} + {} = {}", dice[0], dice[1], dice[2], total);

    // Signed range with negative bounds.
    println!("\ngen_range_i32(-50..50):");
    for _ in 0..5 {
        println!("  {}", rng.gen_range_i32(-50..50));
    }

    // Float range — uniform [0.0, 1.0).
    println!("\ngen_range_f64(0.0..1.0):");
    for _ in 0..5 {
        println!("  {:.6}", rng.gen_range_f64(0.0..1.0));
    }

    // Float range with arbitrary bounds.
    println!("\ngen_range_f64(-100.0..100.0):");
    for _ in 0..5 {
        println!("  {:.3}", rng.gen_range_f64(-100.0..100.0));
    }

    #[cfg(feature = "tier2")]
    {
        use mod_rand::tier2;

        println!("\n\n=== Tier 2 — process-unique bounded ranges ===\n");
        println!("(Output looks random; values are reduced from the");
        println!("unique_u64 stream so they are NOT guaranteed distinct)\n");

        println!("range_inclusive_u32(1..=100):");
        for _ in 0..5 {
            println!("  {}", tier2::range_inclusive_u32(1..=100));
        }

        println!("\nrange_i64(-1_000_000..1_000_000):");
        for _ in 0..5 {
            println!("  {}", tier2::range_i64(-1_000_000..1_000_000));
        }
    }

    #[cfg(feature = "tier3")]
    {
        use mod_rand::tier3;

        println!("\n\n=== Tier 3 — cryptographic bounded ranges ===\n");
        println!("(Each draw is an OS syscall; output unpredictable)\n");

        println!("random_range_inclusive_u32(1..=100):");
        for _ in 0..5 {
            match tier3::random_range_inclusive_u32(1..=100) {
                Ok(n) => println!("  {n}"),
                Err(e) => println!("  ERROR: {e}"),
            }
        }

        // Cryptographically-random secret index into a salt list,
        // useful for choosing among prepared random elements.
        let salt_pool = ["alpha", "bravo", "charlie", "delta", "echo"];
        let idx = tier3::random_range_u32(0..salt_pool.len() as u32).unwrap();
        println!("\nRandomly chosen salt: {}", salt_pool[idx as usize]);

        // Error handling demonstration: empty range returns InvalidInput
        // rather than panicking on Tier 3.
        match tier3::random_range_u64(10..10) {
            Ok(_) => println!("\nunexpected: empty range succeeded"),
            Err(e) => println!("\nEmpty range correctly returned: {e}"),
        }
    }
}
