//! Tier 3 — OS-backed cryptographic microbenchmarks.
//!
//! Run with: `cargo bench --bench tier3`.
//!
//! Each call is a syscall — expect ~100ns to a few hundred ns per
//! call depending on platform and kernel.

#[path = "common.rs"]
mod common;

use common::bench;
use mod_rand::tier3;

fn main() {
    println!("# mod-rand tier3 (OS CSPRNG)\n");

    bench("random_u32", || tier3::random_u32().unwrap());
    bench("random_u64", || tier3::random_u64().unwrap());

    {
        let mut buf = [0u8; 16];
        bench("fill_bytes(16)", || {
            tier3::fill_bytes(&mut buf).unwrap();
            buf[0]
        });
    }
    {
        let mut buf = [0u8; 32];
        bench("fill_bytes(32)", || {
            tier3::fill_bytes(&mut buf).unwrap();
            buf[0]
        });
    }
    {
        let mut buf = [0u8; 1024];
        bench("fill_bytes(1024)", || {
            tier3::fill_bytes(&mut buf).unwrap();
            buf[0]
        });
    }

    bench("random_hex(16)", || tier3::random_hex(16).unwrap());
    bench("random_base32(16)", || tier3::random_base32(16).unwrap());
}
