//! Tier 3 — cryptographic random for tokens, keys, and salts.
//!
//! Demonstrates the API surface most callers reach for: session
//! tokens, API keys, raw-byte keys, password salts.
//!
//! Run with: `cargo run --release --example tier3_token`.

#[cfg(feature = "tier3")]
fn main() -> std::io::Result<()> {
    use mod_rand::tier3;

    // 16-byte session token: 128 bits of entropy, 32 hex chars.
    let session = tier3::random_hex(16)?;
    println!("session token (32-hex):  {session}");

    // 32-byte API key: 256 bits, 64 hex chars — appropriate for
    // long-lived credentials.
    let api_key = tier3::random_hex(32)?;
    println!("api key      (64-hex):  {api_key}");

    // 24-char base32 ID: 120 bits, case-insensitive, filesystem-safe.
    let short_id = tier3::random_base32(24)?;
    println!("short id     (24-b32):  {short_id}");

    // 32-byte raw key, e.g., for AES-256.
    let mut key = [0u8; 32];
    tier3::fill_bytes(&mut key)?;
    print!("raw key      (32 bytes): ");
    for b in key {
        print!("{b:02x}");
    }
    println!();

    Ok(())
}

#[cfg(not(feature = "tier3"))]
fn main() {
    eprintln!("This example requires the `tier3` feature.");
    std::process::exit(1);
}
