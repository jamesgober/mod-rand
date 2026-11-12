//! Tier 2 — process-unique microbenchmarks.
//!
//! Run with: `cargo bench --bench tier2`.
//!
//! Target: <100 ns/call. Cost is dominated by `SystemTime::now()`.

#![allow(deprecated)] // benchmarks the deprecated tier2 string functions

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

    // ------------------------------------------------------------
    // Additional widths and string helpers added in 1.0
    // ------------------------------------------------------------
    println!();

    bench("range_u8(0..100)", || tier2::range_u8(0..100));
    bench("range_u16(0..1000)", || tier2::range_u16(0..1000));
    bench("range_u128(0..u128::MAX/2)", || {
        tier2::range_u128(0..(u128::MAX / 2))
    });
    bench("range_inclusive_u128(0..=u128::MAX)", || {
        tier2::range_inclusive_u128(0..=u128::MAX)
    });
    bench("range_usize(0..1000)", || tier2::range_usize(0..1000));
    bench("range_i128(-1M..1M)", || {
        tier2::range_i128(-1_000_000..1_000_000)
    });

    println!();

    bench("random_alphanumeric(16)", || tier2::random_alphanumeric(16));
    bench("random_alphanumeric(64)", || tier2::random_alphanumeric(64));
    bench("random_hex_string(32)", || tier2::random_hex_string(32));
}
