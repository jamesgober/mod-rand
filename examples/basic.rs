//! Minimal example: show all three tiers in action.
//!
//! Run with: `cargo run --release --example basic`.

use mod_rand::tier1::Xoshiro256;

fn main() {
    println!("Tier 1 — xoshiro256** (deterministic)");
    let mut rng = Xoshiro256::seed_from_u64(42);
    for _ in 0..3 {
        println!("  {:#018x}", rng.next_u64());
    }

    #[cfg(feature = "tier2")]
    {
        println!("\nTier 2 — process-unique");
        for _ in 0..3 {
            println!("  {}", mod_rand::tier2::unique_name(12));
        }
    }

    #[cfg(feature = "tier3")]
    {
        println!("\nTier 3 — cryptographic");
        for _ in 0..3 {
            println!("  {}", mod_rand::tier3::random_hex(16).unwrap());
        }
    }
}
