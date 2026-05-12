//! Tier 2 — process-unique microbenchmarks.
//!
//! Run with: `cargo bench --bench tier2`.
//!
//! Target: <100ns/call. Cost is dominated by `SystemTime::now()`.

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
}
