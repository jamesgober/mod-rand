//! Tier 2 — process-unique temp paths.
//!
//! Demonstrates the canonical use case: a process needs a flurry of
//! distinct identifiers (here, hypothetical tempdir names) that don't
//! need to be unguessable, just non-colliding. Tier 2 is exactly the
//! right shape: ~20–70 ns per call, distinct within a process by
//! construction.
//!
//! Run with: `cargo run --release --example tier2_tempdir`.

#[cfg(feature = "tier2")]
fn main() {
    use mod_rand::tier2;

    println!("Process-unique tempdir-style names (Crockford base32):");
    for _ in 0..5 {
        let name = tier2::unique_name(16);
        println!("  /tmp/build-{name}");
    }

    println!();
    println!("Process-unique trace IDs (hex):");
    for _ in 0..5 {
        let trace = tier2::unique_hex(32);
        println!("  trace-id={trace}");
    }

    println!();
    println!("Raw u64s — every call distinct:");
    for _ in 0..5 {
        println!("  {:#018x}", tier2::unique_u64());
    }
}

#[cfg(not(feature = "tier2"))]
fn main() {
    eprintln!("This example requires the `tier2` feature.");
    std::process::exit(1);
}
