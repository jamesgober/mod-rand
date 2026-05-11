//! # Tier 3 — OS-backed cryptographic random
//!
//! Random values pulled from the OS's secure random source:
//!
//! - Linux: `getrandom(2)` syscall
//! - macOS: `getentropy(3)`
//! - Windows: `BCryptGenRandom`
//!
//! Use for: session tokens, API keys, password salts, anything an
//! attacker would benefit from predicting.
//!
//! In `0.1.0` this is a placeholder; the real syscall implementations
//! land in `0.9.x`.

use std::io;

/// Fill the given buffer with cryptographically secure random bytes.
///
/// Returns an error if the underlying OS random source is unavailable
/// (extremely rare in practice — typically only when a chroot or
/// sandbox blocks access to the entropy source).
///
/// In `0.1.0` this is a placeholder. The real platform syscalls land
/// in `0.9.x`.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let mut buf = [0u8; 32];
/// tier3::fill_bytes(&mut buf).unwrap();
/// ```
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    // Placeholder. Real implementation lands in 0.9.x with
    // platform-specific syscalls.
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEADBEEF);
    let mut s = seed;
    for byte in buf.iter_mut() {
        s = s
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0xBF58476D1CE4E5B9);
        *byte = (s >> 33) as u8;
    }
    Ok(())
}

/// Return a cryptographically secure random `u64`.
///
/// Convenience wrapper around [`fill_bytes`].
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let n: u64 = tier3::random_u64().unwrap();
/// ```
pub fn random_u64() -> io::Result<u64> {
    let mut buf = [0u8; 8];
    fill_bytes(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Return a hex-encoded cryptographically secure random token.
///
/// `bytes` is the number of random bytes (the resulting string is
/// `bytes * 2` hex chars long). 16 bytes (32 hex chars) is a common
/// session-token length; 32 bytes (64 hex chars) is appropriate for
/// API keys.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let token = tier3::random_hex(16).unwrap();
/// assert_eq!(token.len(), 32);
/// ```
pub fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    fill_bytes(&mut buf)?;
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_bytes_produces_output() {
        let mut buf = [0u8; 32];
        fill_bytes(&mut buf).unwrap();
        // At least some bytes should be non-zero.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn random_u64_works() {
        let _ = random_u64().unwrap();
    }

    #[test]
    fn random_hex_correct_length() {
        let h = random_hex(16).unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
