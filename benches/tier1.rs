//! Tier 1 — xoshiro256** microbenchmarks.
//!
//! Run with: `cargo bench --bench tier1`.
//!
//! Target on x86_64: ~1ns/u64.

#[path = "common.rs"]
mod common;

use common::bench;
use mod_rand::tier1::Xoshiro256;

fn main() {
    println!("# mod-rand tier1 (xoshiro256**)\n");

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("next_u64", || rng.next_u64());
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("next_u32", || rng.next_u32());
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("next_f64", || rng.next_f64());
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let mut buf = [0u8; 32];
        bench("fill_bytes(32)", || {
            rng.fill_bytes(&mut buf);
            buf[0]
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let mut buf = [0u8; 4096];
        bench("fill_bytes(4096)", || {
            rng.fill_bytes(&mut buf);
            buf[0]
        });
    }

    {
        bench("seed_from_u64", || Xoshiro256::seed_from_u64(42));
    }
}
