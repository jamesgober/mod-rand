//! Tier 2: process-unique names and IDs.
//!
//! Tier 2 gives a flurry of identifiers that don't need to be
//! unguessable, just distinct: trace IDs, log correlation IDs, and
//! scratch names inside a directory only this process (or user) can
//! write to. About 20 to 70 ns per call.
//!
//! Tier 2 names are predictable. For a file or directory in a shared
//! directory such as `/tmp`, build the name with
//! `tier3::random_base32` instead, create it with `create_new(true)` /
//! `create_dir`, and retry on `AlreadyExists`.
//!
//! Run with: `cargo run --release --example tier2_tempdir`.

#[cfg(feature = "tier2")]
fn main() {
    use mod_rand::tier2;

    println!("Process-unique scratch names for a private directory (Crockford base32):");
    for _ in 0..5 {
        let name = tier2::unique_name(16);
        println!("  ./my-private-cache/build-{name}");
    }

    println!();
    println!("Process-unique trace IDs (hex):");
    for _ in 0..5 {
        let trace = tier2::unique_hex(32);
        println!("  trace-id={trace}");
    }

    println!();
    println!("Raw u64s (distinct with high probability, never secret):");
    for _ in 0..5 {
        println!("  {:#018x}", tier2::unique_u64());
    }
}

#[cfg(not(feature = "tier2"))]
fn main() {
    eprintln!("This example requires the `tier2` feature.");
    std::process::exit(1);
}
