//! Integration tests for the string-generation API added in 1.0.
//!
//! Covers Tier 1 (`Xoshiro256::gen_string` + family), Tier 2
//! (`tier2::random_string` + family), and Tier 3
//! (`tier3::random_string` + family). Each tier:
//!
//! - Returns exactly `len` characters.
//! - Uses only the requested charset (which is always ASCII, so the
//!   returned `String` is valid UTF-8 by construction).
//! - Distributes each character uniformly over the charset.
//! - Rejects invalid charsets (empty / non-ASCII).

#![cfg(all(feature = "tier2", feature = "tier3"))]

use mod_rand::charsets;
use mod_rand::tier1::Xoshiro256;
use mod_rand::{tier2, tier3};

// ------------------------------------------------------------
// Tier 1
// ------------------------------------------------------------

#[test]
fn tier1_length_and_alphabet_alphanumeric() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    for len in [0, 1, 8, 16, 64, 256] {
        let s = rng.gen_alphanumeric(len);
        assert_eq!(s.len(), len, "len={len}");
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}

#[test]
fn tier1_length_and_alphabet_alpha() {
    let mut rng = Xoshiro256::seed_from_u64(2);
    let s = rng.gen_alpha(128);
    assert_eq!(s.len(), 128);
    assert!(s.chars().all(|c| c.is_ascii_alphabetic()));
}

#[test]
fn tier1_length_and_alphabet_numeric() {
    let mut rng = Xoshiro256::seed_from_u64(3);
    let s = rng.gen_numeric(32);
    assert_eq!(s.len(), 32);
    assert!(s.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn tier1_length_and_alphabet_hex() {
    let mut rng = Xoshiro256::seed_from_u64(4);
    let s = rng.gen_hex(64);
    assert_eq!(s.len(), 64);
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    // gen_hex uses HEX_LOWER specifically.
    assert!(s.chars().all(|c| !c.is_ascii_uppercase()));
}

#[test]
fn tier1_custom_charset() {
    let mut rng = Xoshiro256::seed_from_u64(5);
    let cs = b"!@#$%^&*";
    let s = rng.gen_string(50, cs);
    assert_eq!(s.len(), 50);
    assert!(s.bytes().all(|b| cs.contains(&b)));
}

#[test]
fn tier1_url_safe_base58_base64() {
    let mut rng = Xoshiro256::seed_from_u64(6);
    for cs in [charsets::URL_SAFE, charsets::BASE58, charsets::BASE64] {
        let s = rng.gen_string(64, cs);
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| cs.contains(&b)));
    }
}

#[test]
#[should_panic(expected = "charset must be non-empty")]
fn tier1_empty_charset_panics() {
    let mut rng = Xoshiro256::seed_from_u64(7);
    let _ = rng.gen_string(8, b"");
}

#[test]
#[should_panic(expected = "charset must be ASCII")]
fn tier1_non_ascii_charset_panics() {
    let mut rng = Xoshiro256::seed_from_u64(8);
    let mut cs = [b'A'; 8];
    cs[3] = 0xFF; // Non-ASCII byte.
    let _ = rng.gen_string(8, &cs);
}

#[test]
fn tier1_determinism() {
    let mut a = Xoshiro256::seed_from_u64(99);
    let mut b = Xoshiro256::seed_from_u64(99);
    for _ in 0..32 {
        assert_eq!(a.gen_alphanumeric(10), b.gen_alphanumeric(10));
    }
}

#[test]
fn tier1_alphabet_chi_squared() {
    // 100_000 single-character draws over the 62-char ALPHANUMERIC
    // alphabet — expected ~1613 per bucket. Critical value for 61
    // d.f. at alpha=0.001 is ~111; cap at 200 to keep stable.
    let mut rng = Xoshiro256::seed_from_u64(0xC0FFEE);
    let s = rng.gen_alphanumeric(100_000);
    let mut counts = [0u32; 62];
    for b in s.bytes() {
        let idx = charsets::ALPHANUMERIC.iter().position(|&c| c == b).unwrap();
        counts[idx] += 1;
    }
    let expected = 100_000.0 / 62.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    assert!(chi < 200.0, "alphabet chi-squared {chi} too high");
}

// ------------------------------------------------------------
// Tier 2
// ------------------------------------------------------------

#[test]
fn tier2_length_alphabet_alphanumeric() {
    for len in [0, 1, 8, 16, 64, 256] {
        let s = tier2::random_alphanumeric(len);
        assert_eq!(s.len(), len);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}

#[test]
fn tier2_length_alphabet_others() {
    let a = tier2::random_alpha(50);
    let n = tier2::random_numeric(20);
    let h = tier2::random_hex_string(32);
    assert_eq!(a.len(), 50);
    assert_eq!(n.len(), 20);
    assert_eq!(h.len(), 32);
    assert!(a.chars().all(|c| c.is_ascii_alphabetic()));
    assert!(n.chars().all(|c| c.is_ascii_digit()));
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn tier2_random_vs_unique() {
    // `random_*` makes no uniqueness claim; `unique_*` does. Verify
    // that `unique_name` retains its uniqueness guarantee even after
    // `random_*` is added to the same module.
    use std::collections::HashSet;
    let mut set = HashSet::with_capacity(10_000);
    for _ in 0..10_000 {
        assert!(set.insert(tier2::unique_name(16)));
    }
    // And `random_*` produces correctly-typed strings without claim.
    for _ in 0..1000 {
        let s = tier2::random_alphanumeric(8);
        assert_eq!(s.len(), 8);
    }
}

#[test]
fn tier2_custom_charset_with_url_safe() {
    let s = tier2::random_string(40, charsets::URL_SAFE);
    assert_eq!(s.len(), 40);
    assert!(s.bytes().all(|b| charsets::URL_SAFE.contains(&b)));
}

#[test]
#[should_panic(expected = "charset must be non-empty")]
fn tier2_empty_charset_panics() {
    let _ = tier2::random_string(8, b"");
}

// ------------------------------------------------------------
// Tier 3
// ------------------------------------------------------------

#[test]
fn tier3_length_alphabet_alphanumeric() {
    for len in [0, 1, 8, 16, 64] {
        let s = tier3::random_alphanumeric(len).unwrap();
        assert_eq!(s.len(), len);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}

#[test]
fn tier3_length_alphabet_others() {
    let a = tier3::random_alpha(32).unwrap();
    let n = tier3::random_numeric(12).unwrap();
    let h = tier3::random_hex_string(48).unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(n.len(), 12);
    assert_eq!(h.len(), 48);
    assert!(a.chars().all(|c| c.is_ascii_alphabetic()));
    assert!(n.chars().all(|c| c.is_ascii_digit()));
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn tier3_custom_charset_base58() {
    let s = tier3::random_string(40, charsets::BASE58).unwrap();
    assert_eq!(s.len(), 40);
    assert!(s.bytes().all(|b| charsets::BASE58.contains(&b)));
}

#[test]
fn tier3_empty_charset_returns_invalid_input() {
    let err = tier3::random_string(8, b"").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn tier3_non_ascii_charset_returns_invalid_input() {
    let cs = b"\xFF\xFEABCD";
    let err = tier3::random_string(8, cs).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn tier3_random_hex_byte_form_and_string_form_differ() {
    // `random_hex(bytes)` returns `bytes * 2` characters.
    // `random_hex_string(len)` returns `len` characters.
    // Both should work and produce hex output.
    let a = tier3::random_hex(8).unwrap();
    assert_eq!(a.len(), 16);
    let b = tier3::random_hex_string(16).unwrap();
    assert_eq!(b.len(), 16);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(b.chars().all(|c| c.is_ascii_hexdigit()));
}
