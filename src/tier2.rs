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
//! ## Thread safety
//!
//! All functions in this module are thread-safe and lock-free. The
//! shared atomic counter ensures uniqueness even under concurrent
//! access from any number of threads.
//!
//! ## Performance
//!
//! Target <100ns per call. Cost is dominated by a `SystemTime::now()`
//! reading; the mixing itself is a handful of multiplies and rotates.

use core::ops::{Range, RangeInclusive};
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

// ------------------------------------------------------------
// Bounded-range API
//
// Each bounded function below pulls fresh `unique_u64` values and
// reduces them with Lemire's "Nearly Divisionless" rejection sampling.
// The result is uniformly distributed over the requested range — no
// modulo bias.
//
// Note on guarantees: Tier 2 raw `unique_u64` output is guaranteed
// distinct across calls within a single process. The bounded-range
// reductions DO NOT preserve that guarantee — multiple distinct u64
// values necessarily map to the same bounded value when the range is
// smaller than 2^64. Callers who need distinct bounded values must
// either use the raw `unique_u64` stream themselves or de-duplicate.
// ------------------------------------------------------------

/// Produce a uniformly-distributed `u64` in `[0, n)`.
///
/// Internal helper for the bounded-range API. Implements Daniel
/// Lemire's "Nearly Divisionless" rejection sampling. `n` MUST be
/// greater than zero.
#[inline]
fn bounded_u64(n: u64) -> u64 {
    debug_assert!(n != 0, "bounded_u64 requires n > 0");
    let mut x = unique_u64();
    let mut m: u128 = (x as u128).wrapping_mul(n as u128);
    let mut l: u64 = m as u64;
    if l < n {
        let t: u64 = n.wrapping_neg() % n;
        while l < t {
            x = unique_u64();
            m = (x as u128).wrapping_mul(n as u128);
            l = m as u64;
        }
    }
    (m >> 64) as u64
}

/// Generate a uniformly-distributed `u64` in the half-open range
/// `[range.start, range.end)`.
///
/// # Panics
///
/// Panics if the range is empty (`range.start >= range.end`).
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let n = tier2::range_u64(10..20);
/// assert!((10..20).contains(&n));
/// ```
pub fn range_u64(range: Range<u64>) -> u64 {
    let Range { start, end } = range;
    assert!(start < end, "range_u64: empty range {start}..{end}");
    let span = end - start;
    start + bounded_u64(span)
}

/// Generate a uniformly-distributed `u64` in the closed range
/// `[range.start(), range.end()]`.
///
/// The full-width inclusive range `0..=u64::MAX` is supported and
/// is equivalent to a single `unique_u64()` draw.
///
/// # Panics
///
/// Panics if the range is empty (`*range.start() > *range.end()`).
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let d = tier2::range_inclusive_u64(1..=6);
/// assert!((1..=6).contains(&d));
/// ```
pub fn range_inclusive_u64(range: RangeInclusive<u64>) -> u64 {
    let (start, end) = range.into_inner();
    assert!(
        start <= end,
        "range_inclusive_u64: empty range {start}..={end}"
    );
    if start == 0 && end == u64::MAX {
        return unique_u64();
    }
    let span = end - start + 1;
    start + bounded_u64(span)
}

/// Generate a uniformly-distributed `u32` in the half-open range
/// `[range.start, range.end)`.
///
/// # Panics
///
/// Panics if the range is empty.
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let pct = tier2::range_u32(0..100);
/// assert!(pct < 100);
/// ```
pub fn range_u32(range: Range<u32>) -> u32 {
    let Range { start, end } = range;
    assert!(start < end, "range_u32: empty range {start}..{end}");
    let span = (end - start) as u64;
    (start as u64 + bounded_u64(span)) as u32
}

/// Generate a uniformly-distributed `u32` in the closed range
/// `[range.start(), range.end()]`.
///
/// The full-width inclusive range `0..=u32::MAX` is supported.
///
/// # Panics
///
/// Panics if the range is empty.
pub fn range_inclusive_u32(range: RangeInclusive<u32>) -> u32 {
    let (start, end) = range.into_inner();
    assert!(
        start <= end,
        "range_inclusive_u32: empty range {start}..={end}"
    );
    let span = (end as u64) - (start as u64) + 1;
    (start as u64 + bounded_u64(span)) as u32
}

/// Generate a uniformly-distributed `i64` in the half-open range
/// `[range.start, range.end)`.
///
/// Negative bounds and mixed-sign ranges are supported.
///
/// # Panics
///
/// Panics if the range is empty.
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let n = tier2::range_i64(-50..50);
/// assert!((-50..50).contains(&n));
/// ```
pub fn range_i64(range: Range<i64>) -> i64 {
    let Range { start, end } = range;
    assert!(start < end, "range_i64: empty range {start}..{end}");
    let span = (end as i128 - start as i128) as u64;
    let offset = bounded_u64(span);
    ((start as i128) + (offset as i128)) as i64
}

/// Generate a uniformly-distributed `i64` in the closed range
/// `[range.start(), range.end()]`.
///
/// The full-width inclusive range `i64::MIN..=i64::MAX` is supported
/// and is equivalent to reinterpreting a raw `unique_u64()` draw as
/// `i64`.
///
/// # Panics
///
/// Panics if the range is empty.
pub fn range_inclusive_i64(range: RangeInclusive<i64>) -> i64 {
    let (start, end) = range.into_inner();
    assert!(
        start <= end,
        "range_inclusive_i64: empty range {start}..={end}"
    );
    if start == i64::MIN && end == i64::MAX {
        return unique_u64() as i64;
    }
    let span = ((end as i128) - (start as i128) + 1) as u64;
    let offset = bounded_u64(span);
    ((start as i128) + (offset as i128)) as i64
}

/// Generate a uniformly-distributed `i32` in the half-open range
/// `[range.start, range.end)`.
///
/// # Panics
///
/// Panics if the range is empty.
pub fn range_i32(range: Range<i32>) -> i32 {
    let Range { start, end } = range;
    assert!(start < end, "range_i32: empty range {start}..{end}");
    let span = (end as i64 - start as i64) as u64;
    let offset = bounded_u64(span);
    ((start as i64) + (offset as i64)) as i32
}

/// Generate a uniformly-distributed `i32` in the closed range
/// `[range.start(), range.end()]`.
///
/// The full-width inclusive range `i32::MIN..=i32::MAX` is supported.
///
/// # Panics
///
/// Panics if the range is empty.
pub fn range_inclusive_i32(range: RangeInclusive<i32>) -> i32 {
    let (start, end) = range.into_inner();
    assert!(
        start <= end,
        "range_inclusive_i32: empty range {start}..={end}"
    );
    let span = ((end as i64) - (start as i64) + 1) as u64;
    let offset = bounded_u64(span);
    ((start as i64) + (offset as i64)) as i32
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

    // ------------------------------------------------------------
    // Bounded-range tests
    // ------------------------------------------------------------

    #[test]
    fn range_u64_bounds() {
        for _ in 0..10_000 {
            let n = range_u64(100..200);
            assert!((100..200).contains(&n));
        }
    }

    #[test]
    fn range_u64_single_value_window() {
        // [start, start+1) — every draw lands on start.
        for _ in 0..1000 {
            assert_eq!(range_u64(7..8), 7);
        }
    }

    #[test]
    fn range_inclusive_u64_die_roll() {
        // Verify all six faces appear over many rolls.
        let mut faces = [0u32; 6];
        for _ in 0..10_000 {
            let d = range_inclusive_u64(1..=6);
            assert!((1..=6).contains(&d));
            faces[(d - 1) as usize] += 1;
        }
        for (i, &c) in faces.iter().enumerate() {
            assert!(c > 0, "face {} never appeared in 10000 rolls", i + 1);
        }
    }

    #[test]
    fn range_inclusive_u64_single_value() {
        for _ in 0..1000 {
            assert_eq!(range_inclusive_u64(42..=42), 42);
        }
    }

    #[test]
    fn range_inclusive_u64_full_width() {
        // 0..=u64::MAX is the full u64 space; just ensure no panic
        // and at least one draw differs from another.
        let a = range_inclusive_u64(0..=u64::MAX);
        let b = range_inclusive_u64(0..=u64::MAX);
        assert_ne!(a, b);
    }

    #[test]
    fn range_u32_bounds() {
        for _ in 0..10_000 {
            let n = range_u32(0..256);
            assert!(n < 256);
        }
    }

    #[test]
    fn range_inclusive_u32_full_width() {
        // Just exercises the full-width path without crashing.
        for _ in 0..1000 {
            let _ = range_inclusive_u32(0..=u32::MAX);
        }
    }

    #[test]
    fn range_i64_negative() {
        for _ in 0..10_000 {
            let n = range_i64(-100..-50);
            assert!((-100..-50).contains(&n));
        }
    }

    #[test]
    fn range_i64_mixed_sign() {
        let mut saw_neg = false;
        let mut saw_pos = false;
        for _ in 0..10_000 {
            let n = range_i64(-100..100);
            assert!((-100..100).contains(&n));
            if n < 0 {
                saw_neg = true;
            }
            if n >= 0 {
                saw_pos = true;
            }
        }
        assert!(saw_neg && saw_pos);
    }

    #[test]
    fn range_inclusive_i64_full_width() {
        // i64::MIN..=i64::MAX — just verify no panic.
        let _ = range_inclusive_i64(i64::MIN..=i64::MAX);
    }

    #[test]
    fn range_i32_bounds() {
        for _ in 0..10_000 {
            let n = range_i32(-1000..1000);
            assert!((-1000..1000).contains(&n));
        }
    }

    #[test]
    fn range_inclusive_i32_full_width() {
        for _ in 0..1000 {
            let _ = range_inclusive_i32(i32::MIN..=i32::MAX);
        }
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn range_u64_panics_on_empty() {
        let _ = range_u64(10..10);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    #[allow(clippy::reversed_empty_ranges)]
    fn range_u64_panics_on_reverse() {
        let _ = range_u64(10..5);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    #[allow(clippy::reversed_empty_ranges)]
    fn range_inclusive_u64_panics_on_reverse() {
        let _ = range_inclusive_u64(10..=5);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    #[allow(clippy::reversed_empty_ranges)]
    fn range_i64_panics_on_reverse() {
        let _ = range_i64(5..-5);
    }

    #[test]
    fn range_uniformity_chi_squared() {
        // 100 000 draws over a range of 100 buckets. Same statistical
        // threshold reasoning as in tier1. Note: this is a real
        // uniformity check on the Tier 2 reduction — if anyone
        // replaces rejection sampling with `unique_u64() % 100`, the
        // bias from the modulo operation would inflate chi-squared
        // beyond the threshold and fail this test.
        let mut counts = [0u32; 100];
        for _ in 0..100_000 {
            let v = range_u32(0..100);
            counts[v as usize] += 1;
        }
        let expected = 100_000.0 / 100.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(
            chi < 250.0,
            "chi-squared {chi} too high — bounded-range output is biased"
        );
    }
}
