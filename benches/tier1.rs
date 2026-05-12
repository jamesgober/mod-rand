//! Tier 1 — xoshiro256** microbenchmarks.
//!
//! Run with: `cargo bench --bench tier1`.
//!
//! Target on x86_64: ~1 ns/u64 for raw draws.

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

    // ------------------------------------------------------------
    // Bounded-range benches
    //
    // These measure the cost of Lemire's rejection sampling on top of
    // the raw xoshiro256** stream. Expect single-digit ns/op overhead
    // on top of the ~0.6 ns/u64 baseline.
    // ------------------------------------------------------------
    println!();

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_u64(0..100)", || rng.gen_range_u64(0..100));
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_inclusive_u32(1..=6)", || {
            rng.gen_range_inclusive_u32(1..=6)
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_i64(-1000..1000)", || {
            rng.gen_range_i64(-1000..1000)
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_f64(-1.0..1.0)", || rng.gen_range_f64(-1.0..1.0));
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        // Worst-case rejection rate: span just over half u64::MAX.
        // Roughly 1/3 of draws get rejected, so expected calls per
        // output is ~1.5. This is the hardest case for Lemire.
        let s = (u64::MAX / 3) * 2;
        bench("gen_range_u64(0..2/3*u64::MAX) [worst case]", || {
            rng.gen_range_u64(0..s)
        });
    }
}
