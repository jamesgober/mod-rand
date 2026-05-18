//! # Charset constants
//!
//! Byte-slice constants for the most common ASCII character sets used
//! by mod-rand's string-generation helpers (`gen_string`,
//! `random_string`, etc.). Each constant is a `&'static [u8]` of ASCII
//! bytes (every byte < 128); no allocation, no `String` wrappers.
//!
//! All constants here are available in `no_std`.
//!
//! ## Picking a charset
//!
//! - [`ALPHANUMERIC`] — the default for most random IDs (62 chars).
//! - [`ALPHA_LOWER`] / [`ALPHA_UPPER`] — when case must be uniform.
//! - [`HEX_LOWER`] / [`HEX_UPPER`] — for tokens that need only
//!   hex-safe characters (logging, color codes, raw byte tokens).
//! - [`URL_SAFE`] — RFC 4648 §5 URL-safe alphabet. Safe in URL paths
//!   and query strings without percent-encoding.
//! - [`BASE58`] — Bitcoin's alphabet. Omits visually-ambiguous
//!   characters (`0`, `O`, `I`, `l`).
//! - [`BASE64`] — RFC 4648 §4 standard. **Includes `+` and `/`**,
//!   which require percent-encoding in URLs; use [`URL_SAFE`] for
//!   URL contexts.
//!
//! ## Custom charsets
//!
//! Every `gen_string` / `random_string` entry point also accepts a
//! caller-supplied `&[u8]`. The caller MUST provide an ASCII charset
//! (every byte < 128); the string-generation helpers reject non-ASCII
//! charsets with a panic (Tier 1, Tier 2) or `io::Error` (Tier 3) so
//! the resulting `String` is never a malformed UTF-8 sequence.
//!
//! ## Example
//!
//! ```
//! use mod_rand::charsets;
//! use mod_rand::tier1::Xoshiro256;
//!
//! let mut rng = Xoshiro256::seed_from_u64(1);
//! let id = rng.gen_string(12, charsets::ALPHANUMERIC);
//! assert_eq!(id.len(), 12);
//! ```

/// All ASCII letters and digits — `A-Z`, `a-z`, `0-9`. 62 characters.
///
/// The most common default for random identifiers: roughly 5.95 bits
/// of entropy per character, no special characters, case-sensitive.
pub const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// ASCII letters only — `A-Z`, `a-z`. 52 characters.
pub const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Lowercase ASCII letters — `a-z`. 26 characters.
pub const ALPHA_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// Uppercase ASCII letters — `A-Z`. 26 characters.
pub const ALPHA_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// ASCII digits — `0-9`. 10 characters.
pub const NUMERIC: &[u8] = b"0123456789";

/// Lowercase hex digits — `0-9`, `a-f`. 16 characters.
pub const HEX_LOWER: &[u8] = b"0123456789abcdef";

/// Uppercase hex digits — `0-9`, `A-F`. 16 characters.
pub const HEX_UPPER: &[u8] = b"0123456789ABCDEF";

/// URL-safe base64 alphabet — RFC 4648 §5. `A-Z`, `a-z`, `0-9`, `-`,
/// `_`. 64 characters.
///
/// Safe to embed directly in URL paths and query strings without
/// percent-encoding.
pub const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base58 alphabet (Bitcoin / Flickr). Omits the visually-ambiguous
/// `0`, `O`, `I`, `l`. 58 characters.
pub const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Standard base64 alphabet — RFC 4648 §4. `A-Z`, `a-z`, `0-9`, `+`,
/// `/`. 64 characters.
///
/// Note: `+` and `/` require percent-encoding in URL contexts; prefer
/// [`URL_SAFE`] when generating identifiers that go into URLs.
pub const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_lengths() {
        assert_eq!(ALPHANUMERIC.len(), 62);
        assert_eq!(ALPHA.len(), 52);
        assert_eq!(ALPHA_LOWER.len(), 26);
        assert_eq!(ALPHA_UPPER.len(), 26);
        assert_eq!(NUMERIC.len(), 10);
        assert_eq!(HEX_LOWER.len(), 16);
        assert_eq!(HEX_UPPER.len(), 16);
        assert_eq!(URL_SAFE.len(), 64);
        assert_eq!(BASE58.len(), 58);
        assert_eq!(BASE64.len(), 64);
    }

    #[test]
    fn all_charsets_are_ascii() {
        for cs in [
            ALPHANUMERIC,
            ALPHA,
            ALPHA_LOWER,
            ALPHA_UPPER,
            NUMERIC,
            HEX_LOWER,
            HEX_UPPER,
            URL_SAFE,
            BASE58,
            BASE64,
        ] {
            assert!(cs.iter().all(|&b| b < 128), "non-ASCII byte in charset");
        }
    }

    #[test]
    fn base58_omits_ambiguous() {
        for &b in BASE58 {
            let c = b as char;
            assert!(
                !matches!(c, '0' | 'O' | 'I' | 'l'),
                "base58 must omit ambiguous {c}"
            );
        }
    }

    #[test]
    fn no_duplicates_within_charset() {
        for cs in [
            ALPHANUMERIC,
            ALPHA,
            ALPHA_LOWER,
            ALPHA_UPPER,
            NUMERIC,
            HEX_LOWER,
            HEX_UPPER,
            URL_SAFE,
            BASE58,
            BASE64,
        ] {
            for (i, &b) in cs.iter().enumerate() {
                assert!(!cs[i + 1..].contains(&b), "duplicate byte {b} in charset");
            }
        }
    }
}
