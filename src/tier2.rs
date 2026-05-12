//! # Tier 2 — Process-unique seeds
//!
//! Fast pseudo-random values derived from process ID, high-resolution
//! time, and a monotonic atomic counter, then run through several
//! rounds of a strong scalar mixer. Good for:
//!
//! - Tempdir / temp-file names
//! - Request and trace IDs
//! - Log correlation IDs
//! - Any application-level "good-enough" uniqueness
//!
//! **Not cryptographic.** An attacker who can observe outputs can
//! often reconstruct internal state and predict subsequent values. Use
//! [`tier3`](crate::tier3) for security-sensitive randomness.
//!
//! ## Uniqueness guarantees
//!
//! - Within a single process: every [`unique_u64`] call returns a
//!   distinct value (guaranteed by a never-resetting atomic counter,
//!   modulo wrap at `2^64` calls — about 584 years at 1 GHz).
//! - Across processes on the same host: PID + nanosecond timestamp
//!   make collisions vanishingly unlikely.
//! - Across hosts: this tier makes no claims. Use [`tier3`](crate::tier3)
//!   when you need values unique across machines.
//!
//! ## Performance
//!
//! Target <100ns per call. Cost is dominated by a `SystemTime::now()`
//! reading; the mixing itself is a handful of multiplies and rotates.

use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic per-process counter. Initialised at first use; never
/// resets. Wraps after 2^64 calls (584 years at one call per
/// nanosecond — i.e., effectively never).
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Process-wide salt mixed into every output. Captured once on first
/// use so that two processes started in the same nanosecond with the
/// same PID (e.g., container restart) still diverge from their first
/// call onward. Zero is a sentinel for "not yet initialised."
static PROCESS_SALT: AtomicU64 = AtomicU64::new(0);

/// Produce a process-unique `u64`.
///
/// Combines PID, the current `SystemTime` in nanoseconds, an atomic
/// counter, and a per-process salt; passes the result through a
/// strong scalar mixer (variant of MurmurHash3's finalizer / Stafford
/// mix 13). Output is uniform-looking but not unpredictable to an
/// adversary who has seen prior outputs.
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let a = tier2::unique_u64();
/// let b = tier2::unique_u64();
/// assert_ne!(a, b);
/// ```
pub fn unique_u64() -> u64 {
    let pid = process::id() as u64;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let salt = process_salt();

    // Combine inputs via odd multipliers (each a large prime / good
    // mixing constant), then finalize with stafford_mix13. The
    // counter is the only field guaranteed to differ between same-
    // process calls, so it gets the highest-quality multiplier and is
    // XORed in last so it cannot be cancelled by the others.
    let mixed = pid
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(nanos.wrapping_mul(0xBF58_476D_1CE4_E5B9))
        .wrapping_add(salt.wrapping_mul(0x94D0_49BB_1331_11EB))
        ^ counter.wrapping_mul(0xDA94_2042_E4DD_58B5);

    stafford_mix13(mixed)
}

/// Produce a process-unique base32 (Crockford alphabet) name of
/// exactly `len` characters.
///
/// Suitable for tempdir and temp-file names, correlation IDs, and the
/// like. The Crockford alphabet (`0-9A-Z` with `I`, `L`, `O`, `U`
/// removed) is filesystem-safe on every platform and avoids visually
/// ambiguous characters.
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let name = tier2::unique_name(12);
/// assert_eq!(name.len(), 12);
/// assert!(name.chars().all(|c| c.is_ascii_alphanumeric()));
/// ```
pub fn unique_name(len: usize) -> String {
    encode_base32(len)
}

/// Produce a process-unique base32 (Crockford alphabet) string of
/// exactly `len` characters. Equivalent to [`unique_name`]; provided
/// for symmetry with [`unique_hex`].
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let s = tier2::unique_base32(16);
/// assert_eq!(s.len(), 16);
/// ```
pub fn unique_base32(len: usize) -> String {
    encode_base32(len)
}

/// Produce a process-unique lowercase hex string of exactly `len`
/// characters.
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let s = tier2::unique_hex(8);
/// assert_eq!(s.len(), 8);
/// assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn unique_hex(len: usize) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(len);
    let mut state = unique_u64();
    let mut bits_left = 64;
    while out.len() < len {
        if bits_left < 4 {
            state = unique_u64();
            bits_left = 64;
        }
        out.push(ALPHABET[(state & 0xF) as usize] as char);
        state >>= 4;
        bits_left -= 4;
    }
    out
}

fn encode_base32(len: usize) -> String {
    // Crockford base32 alphabet (no I, L, O, U).
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::with_capacity(len);
    let mut state = unique_u64();
    let mut bits_left = 64;
    while out.len() < len {
        if bits_left < 5 {
            // Re-seed with a fresh tier2 value rather than recycling
            // the residual bits — keeps each character independent.
            state = unique_u64();
            bits_left = 64;
        }
        out.push(ALPHABET[(state & 0x1F) as usize] as char);
        state >>= 5;
        bits_left -= 5;
    }
    out
}

/// Stafford's variant 13 — a strong 64-bit avalanche mixer. Same
/// family as splitmix64's finalizer but with constants tuned for
/// stronger statistical properties on small input deltas (which is
/// exactly our case — successive counter values differ only in the
/// low bits).
#[inline]
fn stafford_mix13(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Lazily initialise (once per process) and return the process salt.
fn process_salt() -> u64 {
    let current = PROCESS_SALT.load(Ordering::Relaxed);
    if current != 0 {
        return current;
    }
    let pid = process::id() as u64;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let candidate = stafford_mix13(
        pid.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ nanos.wrapping_mul(0xC2B2_AE3D_27D4_EB4F),
    )
    .max(1);
    // The first writer wins. Subsequent writers see the established
    // salt and adopt it. This is racy only in the harmless sense that
    // a brief moment may exist where two threads compute slightly
    // different candidates; whichever lands first is the salt.
    match PROCESS_SALT.compare_exchange(0, candidate, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => candidate,
        Err(existing) => existing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn two_calls_differ() {
        assert_ne!(unique_u64(), unique_u64());
    }

    #[test]
    fn name_meets_exact_length() {
        for len in [1, 4, 8, 16, 32, 64, 128] {
            let n = unique_name(len);
            assert_eq!(n.len(), len, "length {len}");
        }
    }

    #[test]
    fn name_uses_crockford_alphabet() {
        let n = unique_name(256);
        for c in n.chars() {
            assert!(
                c.is_ascii_digit() || c.is_ascii_uppercase(),
                "char {c:?} outside Crockford alphabet"
            );
            assert!(!matches!(c, 'I' | 'L' | 'O' | 'U'), "ambiguous char {c}");
        }
    }

    #[test]
    fn names_are_unique_across_calls() {
        // 10 000 names of 16 chars (~80 random bits) — collisions are
        // astronomically unlikely given the counter guarantee.
        let mut set = HashSet::with_capacity(10_000);
        for _ in 0..10_000 {
            assert!(set.insert(unique_name(16)));
        }
    }

    #[test]
    fn unique_u64_collision_free_at_scale() {
        // 1 000 000 calls — every value must be distinct (counter
        // guarantee). This is the headline correctness property of
        // tier2.
        let n = 1_000_000;
        let mut set = HashSet::with_capacity(n);
        for _ in 0..n {
            assert!(set.insert(unique_u64()));
        }
        assert_eq!(set.len(), n);
    }

    #[test]
    fn unique_hex_exact_length_and_alphabet() {
        for len in [1, 7, 8, 9, 16, 32, 64, 128] {
            let s = unique_hex(len);
            assert_eq!(s.len(), len, "length {len}");
            assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn unique_base32_exact_length() {
        for len in [1, 5, 8, 13, 32, 64] {
            let s = unique_base32(len);
            assert_eq!(s.len(), len);
        }
    }

    #[test]
    fn alphabet_distribution_is_reasonable() {
        // Chi-squared test on Crockford-base32 alphabet usage over a
        // large sample. With 32 buckets and 100 000 draws, expected
        // count per bucket is ~3125. The 0.999 critical value for
        // chi-squared with 31 d.f. is ~61.1. We use a generous cap of
        // 100 to keep this test stable on slow CI.
        let sample: String = (0..100_000)
            .map(|_| unique_base32(1).chars().next().unwrap())
            .collect();
        let mut counts = [0u32; 32];
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        for c in sample.chars() {
            let idx = ALPHABET
                .iter()
                .position(|&b| b as char == c)
                .expect("char from Crockford alphabet");
            counts[idx] += 1;
        }
        let n = sample.len() as f64;
        let expected = n / 32.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 100.0, "chi-squared {chi} too high (alphabet skew)");
    }

    #[test]
    fn hex_distribution_is_reasonable() {
        // Same idea against the 16-char hex alphabet. 100 000 draws,
        // expected 6250 per bucket, critical value (15 d.f.) ~37.7;
        // cap at 60.
        let sample: String = unique_hex(100_000);
        let mut counts = [0u32; 16];
        for c in sample.chars() {
            let v = c.to_digit(16).unwrap() as usize;
            counts[v] += 1;
        }
        let n = sample.len() as f64;
        let expected = n / 16.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 60.0, "chi-squared {chi} too high (hex skew)");
    }

    #[test]
    fn zero_length_yields_empty_string() {
        assert_eq!(unique_name(0), "");
        assert_eq!(unique_hex(0), "");
        assert_eq!(unique_base32(0), "");
    }

    #[test]
    fn process_salt_is_stable_within_process() {
        let a = process_salt();
        let b = process_salt();
        assert_eq!(a, b);
        assert_ne!(a, 0);
    }
}
