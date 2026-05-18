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

    // ------------------------------------------------------------
    // Additional integer widths added in 1.0
    // ------------------------------------------------------------
    println!();

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_u8(0..100)", || rng.gen_range_u8(0..100));
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_u16(0..1000)", || rng.gen_range_u16(0..1000));
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_u128(0..u128::MAX/2)", || {
            rng.gen_range_u128(0..(u128::MAX / 2))
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_inclusive_u128(0..=u128::MAX)", || {
            rng.gen_range_inclusive_u128(0..=u128::MAX)
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_usize(0..1000)", || rng.gen_range_usize(0..1000));
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_range_i128(-1M..1M)", || {
            rng.gen_range_i128(-1_000_000..1_000_000)
        });
    }

    // ------------------------------------------------------------
    // Distribution helpers added in 1.0
    // ------------------------------------------------------------
    println!();

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_f64", || rng.gen_f64());
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_f32", || rng.gen_f32());
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        bench("gen_bool(0.5)", || rng.gen_bool(0.5));
    }

    // ------------------------------------------------------------
    // String generation (requires `std` for `String` allocation)
    // ------------------------------------------------------------
    #[cfg(feature = "std")]
    {
        println!();

        {
            let mut rng = Xoshiro256::seed_from_u64(42);
            bench("gen_alphanumeric(16)", || rng.gen_alphanumeric(16));
        }

        {
            let mut rng = Xoshiro256::seed_from_u64(42);
            bench("gen_alphanumeric(64)", || rng.gen_alphanumeric(64));
        }

        {
            let mut rng = Xoshiro256::seed_from_u64(42);
            bench("gen_hex(32)", || rng.gen_hex(32));
        }
    }

    // ------------------------------------------------------------
    // Collection ops
    // ------------------------------------------------------------
    println!();

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let mut v: Vec<u32> = (0..10).collect();
        bench("shuffle(10)", || {
            rng.shuffle(&mut v);
            v[0]
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let mut v: Vec<u32> = (0..100).collect();
        bench("shuffle(100)", || {
            rng.shuffle(&mut v);
            v[0]
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let mut v: Vec<u32> = (0..1000).collect();
        bench("shuffle(1000)", || {
            rng.shuffle(&mut v);
            v[0]
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let mut v: Vec<u32> = (0..10_000).collect();
        bench("shuffle(10000)", || {
            rng.shuffle(&mut v);
            v[0]
        });
    }

    #[cfg(feature = "std")]
    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let pool: Vec<u32> = (0..1000).collect();
        bench("sample(k=10, n=1000)", || rng.sample(&pool, 10).len());
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let weights = vec![1.0_f64; 10];
        bench("weighted_index(10 weights)", || {
            rng.weighted_index(&weights)
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let weights = vec![1.0_f64; 100];
        bench("weighted_index(100 weights)", || {
            rng.weighted_index(&weights)
        });
    }

    {
        let mut rng = Xoshiro256::seed_from_u64(42);
        let weights = vec![1.0_f64; 1000];
        bench("weighted_index(1000 weights)", || {
            rng.weighted_index(&weights)
        });
    }
}
