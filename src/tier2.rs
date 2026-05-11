//! # Tier 2 — Process-unique seeds
//!
//! Random values derived from process ID, high-resolution time, and
//! an atomic counter. Good for: tempdir names, request IDs, log
//! correlation IDs, "good enough" uniqueness.
//!
//! **Not cryptographic.** An attacker who can observe outputs can
//! often predict subsequent values. Use [`tier3`](crate::tier3) for
//! security-sensitive randomness.

use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Produce a process-unique `u64`.
///
/// Combines PID, current nanoseconds since UNIX_EPOCH, and an atomic
/// counter. Two calls in the same process produce different values
/// (guaranteed by the counter). Two processes are extremely unlikely
/// to produce the same value (PID + nanos varies).
///
/// In `0.1.0` this is a placeholder. The real mixing function lands
/// in `0.9.x`.
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

    // Placeholder mixing. Real mix function (probably a few rounds of
    // xorshift) lands in 0.9.x.
    pid.wrapping_mul(0x9E3779B97F4A7C15)
        ^ nanos.wrapping_mul(0xBF58476D1CE4E5B9)
        ^ counter.wrapping_mul(0x94D049BB133111EB)
}

/// Produce a base32-encoded unique name of approximately `len` characters.
///
/// Suitable for tempdir naming, correlation IDs, etc.
///
/// In `0.1.0` this is a placeholder.
///
/// # Example
///
/// ```
/// use mod_rand::tier2;
///
/// let name = tier2::unique_name(8);
/// assert!(name.len() >= 8);
/// ```
pub fn unique_name(len: usize) -> String {
    // Crockford base32 alphabet (no I, L, O, U to avoid confusion).
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::with_capacity(len);
    let mut state = unique_u64();
    while out.len() < len {
        out.push(ALPHABET[(state & 31) as usize] as char);
        state >>= 5;
        if state == 0 {
            state = unique_u64();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_calls_differ() {
        assert_ne!(unique_u64(), unique_u64());
    }

    #[test]
    fn name_meets_length() {
        let n = unique_name(8);
        assert!(n.len() >= 8);
    }

    #[test]
    fn names_are_unique_across_calls() {
        let a = unique_name(16);
        let b = unique_name(16);
        assert_ne!(a, b);
    }
}
