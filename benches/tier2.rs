//! Tier 2 — process-unique microbenchmarks.
//!
//! Run with: `cargo bench --bench tier2`.
//!
//! Target: <100 ns/call. Cost is dominated by `SystemTime::now()`.

#[path = "common.rs"]
mod common;

use common::bench;
use mod_rand::tier2;

fn main() {
    println!("# mod-rand tier2 (process-unique)\n");

    bench("unique_u64", tier2::unique_u64);
    bench("unique_name(8)", || tier2::unique_name(8));
    bench("unique_name(16)", || tier2::unique_name(16));
    bench("unique_hex(16)", || tier2::unique_hex(16));
    bench("unique_base32(16)", || tier2::unique_base32(16));

    // ------------------------------------------------------------
    // Bounded-range benches
    //
    // Each bounded call wraps a `unique_u64` plus the rejection
    // sampling step. Expected overhead: a handful of nanoseconds
    // beyond the ~20 ns/unique_u64 baseline.
    // ------------------------------------------------------------
    println!();

    bench("range_u64(0..100)", || tier2::range_u64(0..100));
    bench("range_inclusive_u32(1..=6)", || {
        tier2::range_inclusive_u32(1..=6)
    });
    bench("range_i64(-1000..1000)", || tier2::range_i64(-1000..1000));
    bench("range_inclusive_u64(0..=u64::MAX)", || {
        tier2::range_inclusive_u64(0..=u64::MAX)
    });
}
