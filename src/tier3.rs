//! # Tier 3 — OS-backed cryptographic random
//!
//! Random values pulled directly from the operating system's secure
//! random source. Suitable for tokens, API keys, password salts,
//! session IDs, nonces — anything an attacker would benefit from
//! predicting.
//!
//! ## Source per platform
//!
//! | Platform | Source                                      |
//! |----------|---------------------------------------------|
//! | Linux    | `getrandom(2)` syscall (via libc symbol)    |
//! | macOS    | `getentropy(3)` from libSystem              |
//! | Windows  | `BCryptGenRandom` from `bcrypt.dll`         |
//! | Other Unix | `/dev/urandom` read                       |
//!
//! On Linux, if `getrandom` is unavailable (kernel older than 3.17,
//! which is older than every supported Rust target), the
//! implementation falls back to reading `/dev/urandom`. **`/dev/urandom`
//! is a fully-supported cryptographic source on all listed platforms
//! — the fallback is not a security downgrade.** It is never used as
//! a fallback from a *failed* syscall, only from an *unavailable* one.
//!
//! On every platform, if the OS RNG cannot service the request, the
//! call returns `io::Error`. This module will **never** fall back to
//! a non-cryptographic source.
//!
//! ## Failure modes
//!
//! - On sandboxed processes (Linux seccomp, macOS sandbox) where the
//!   syscall is filtered, you receive `io::Error`.
//! - On Linux at very early boot before the entropy pool has been
//!   seeded, `getrandom` blocks (does not fail). This is the desired
//!   behaviour — predictable boot-time random is the classic
//!   real-world weakness this tier prevents.
//! - On Windows, BCryptGenRandom failures surface the NTSTATUS code
//!   in the returned `io::Error`.
//!
//! ## Thread safety
//!
//! All functions in this module are thread-safe. The underlying
//! syscalls (`getrandom`, `getentropy`, `BCryptGenRandom`) are
//! documented thread-safe by their respective platforms, and the
//! Rust-side wrappers hold no shared mutable state.
//!
//! ## Performance
//!
//! One syscall worth of overhead per call (typically 100–500ns).
//! Amortize by reading 32 or 64 bytes at a time for token generation
//! rather than one byte at a time.

use std::io;

mod sys {
    //! Platform-specific entropy primitives.
    //!
    //! Each platform module exposes a single `fill(buf)` function that
    //! either fills the buffer completely or returns `io::Error`.

    use std::io;

    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// Dispatches to the platform-specific implementation.
    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        platform::fill(buf)
    }

    #[cfg(target_os = "linux")]
    mod platform {
        use std::io;
        use std::sync::atomic::{AtomicU8, Ordering};

        // getrandom(2) — present in glibc >= 2.25 and musl >= 1.1.20.
        // The symbol is resolved at link time; on systems lacking it
        // we'd fail to link, but every supported Rust target ships a
        // libc new enough to provide it.
        //
        // EINTR retry is required because getrandom can be interrupted
        // by signal delivery when buflen > 256.
        extern "C" {
            fn getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize;
            fn __errno_location() -> *mut i32;
        }

        const EINTR: i32 = 4;
        const ENOSYS: i32 = 38;

        // 0 = unknown, 1 = available, 2 = unavailable (use /dev/urandom).
        static STATE: AtomicU8 = AtomicU8::new(0);

        fn errno() -> i32 {
            // SAFETY: __errno_location returns a valid pointer into
            // thread-local storage in every supported libc. The
            // pointer remains valid for the lifetime of the thread.
            unsafe { *__errno_location() }
        }

        pub fn fill(buf: &mut [u8]) -> io::Result<()> {
            if STATE.load(Ordering::Relaxed) == 2 {
                return urandom_fallback(buf);
            }

            let mut pos = 0;
            while pos < buf.len() {
                // SAFETY: buf is a valid &mut [u8]; the pointer and
                // length describe the unfilled tail. flags = 0 selects
                // blocking, /dev/urandom-style behaviour.
                let r = unsafe { getrandom(buf.as_mut_ptr().add(pos), buf.len() - pos, 0) };
                if r > 0 {
                    pos += r as usize;
                    continue;
                }
                let e = errno();
                if e == EINTR {
                    continue;
                }
                if e == ENOSYS {
                    STATE.store(2, Ordering::Relaxed);
                    // Re-attempt the whole fill via /dev/urandom from
                    // the start of the unfilled region.
                    return urandom_fallback(&mut buf[pos..]);
                }
                return Err(io::Error::from_raw_os_error(e));
            }
            STATE.store(1, Ordering::Relaxed);
            Ok(())
        }

        fn urandom_fallback(buf: &mut [u8]) -> io::Result<()> {
            use std::fs::File;
            use std::io::Read;
            let mut f = File::open("/dev/urandom")?;
            f.read_exact(buf)
        }
    }

    #[cfg(target_os = "macos")]
    mod platform {
        use std::io;

        // getentropy(3) — present in macOS 10.12+ via libSystem.
        // Capped at 256 bytes per call.
        extern "C" {
            fn getentropy(buf: *mut u8, buflen: usize) -> i32;
            fn __error() -> *mut i32;
        }

        const EINTR: i32 = 4;
        const MAX_PER_CALL: usize = 256;

        fn errno() -> i32 {
            // SAFETY: __error returns a pointer into thread-local
            // storage; valid for the thread's lifetime.
            unsafe { *__error() }
        }

        pub fn fill(buf: &mut [u8]) -> io::Result<()> {
            for chunk in buf.chunks_mut(MAX_PER_CALL) {
                loop {
                    // SAFETY: chunk is a valid &mut [u8] of length
                    // <= MAX_PER_CALL, satisfying getentropy's
                    // contract.
                    let r = unsafe { getentropy(chunk.as_mut_ptr(), chunk.len()) };
                    if r == 0 {
                        break;
                    }
                    let e = errno();
                    if e == EINTR {
                        continue;
                    }
                    return Err(io::Error::from_raw_os_error(e));
                }
            }
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    mod platform {
        use std::io;

        // BCryptGenRandom from bcrypt.dll. With a NULL algorithm
        // handle plus BCRYPT_USE_SYSTEM_PREFERRED_RNG, the call uses
        // the system's preferred CSPRNG without any caller setup. The
        // call is documented thread-safe and reentrant.
        //
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG is the only flag that
        // permits a NULL algorithm handle. Available since
        // Windows Vista / Server 2008.
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut core::ffi::c_void,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> i32;
        }

        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        // STATUS_SUCCESS — every other NTSTATUS is an error in this API.
        const STATUS_SUCCESS: i32 = 0;

        pub fn fill(buf: &mut [u8]) -> io::Result<()> {
            // cbBuffer is u32; if `buf` somehow exceeds u32::MAX, chunk it.
            // In practice no caller approaches this limit; we handle it
            // for safety rather than out of expected need.
            for chunk in buf.chunks_mut(u32::MAX as usize) {
                // SAFETY: chunk is a valid &mut [u8]; cbBuffer fits in
                // u32 by construction.
                let status = unsafe {
                    BCryptGenRandom(
                        core::ptr::null_mut(),
                        chunk.as_mut_ptr(),
                        chunk.len() as u32,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                    )
                };
                if status != STATUS_SUCCESS {
                    return Err(io::Error::other(format!(
                        "BCryptGenRandom failed: NTSTATUS 0x{:08X}",
                        status as u32
                    )));
                }
            }
            Ok(())
        }
    }

    // Other Unix-like targets (FreeBSD, OpenBSD, NetBSD, illumos,
    // etc.): /dev/urandom is universally available and is a
    // cryptographic source on every one of these. Not a "fallback"
    // from a stronger primitive — it IS the platform primitive here.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    mod platform {
        use std::fs::File;
        use std::io::{self, Read};

        pub fn fill(buf: &mut [u8]) -> io::Result<()> {
            let mut f = File::open("/dev/urandom")?;
            f.read_exact(buf)
        }
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    mod platform {
        use std::io;

        pub fn fill(_buf: &mut [u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mod-rand tier3 has no entropy source on this platform",
            ))
        }
    }
}

/// Fill the given buffer with cryptographically secure random bytes.
///
/// Returns `Ok(())` only if the entire buffer was filled from the
/// platform's secure random source. Returns `io::Error` if the OS
/// random source is unavailable (sandbox, seccomp filter, missing
/// device) — never falls back to a weaker source.
///
/// An empty buffer succeeds without making any syscall.
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
    if buf.is_empty() {
        return Ok(());
    }
    sys::fill(buf)
}

/// Return a cryptographically secure random `u64`.
///
/// Convenience wrapper around [`fill_bytes`]. Uses little-endian byte
/// order; consumers should not rely on this — for randomness, byte
/// order is immaterial.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let n: u64 = tier3::random_u64().unwrap();
/// # let _ = n;
/// ```
pub fn random_u64() -> io::Result<u64> {
    let mut buf = [0u8; 8];
    fill_bytes(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Return a cryptographically secure random `u32`.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let n: u32 = tier3::random_u32().unwrap();
/// # let _ = n;
/// ```
pub fn random_u32() -> io::Result<u32> {
    let mut buf = [0u8; 4];
    fill_bytes(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Return a `Vec<u8>` of cryptographically secure random bytes.
///
/// Convenience for callers who don't already have a buffer.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let bytes = tier3::random_bytes(32).unwrap();
/// assert_eq!(bytes.len(), 32);
/// ```
pub fn random_bytes(len: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    fill_bytes(&mut v)?;
    Ok(v)
}

/// Return a hex-encoded cryptographically secure random token.
///
/// `bytes` is the number of raw random bytes drawn; the resulting
/// string is exactly `bytes * 2` lowercase hex characters long.
///
/// Common sizes:
/// - 16 bytes (32 hex chars) — session tokens
/// - 32 bytes (64 hex chars) — API keys, password reset tokens
/// - 64 bytes (128 hex chars) — long-lived secrets
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let token = tier3::random_hex(16).unwrap();
/// assert_eq!(token.len(), 32);
/// assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn random_hex(bytes: usize) -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = vec![0u8; bytes];
    fill_bytes(&mut buf)?;
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xF) as usize] as char);
    }
    Ok(out)
}

/// Return a Crockford base32-encoded cryptographically secure random
/// token of exactly `chars` characters.
///
/// Each character contributes 5 bits of entropy; the function draws
/// `ceil(chars * 5 / 8)` random bytes and encodes them. Suitable for
/// case-insensitive secrets and filesystem-safe identifiers.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let s = tier3::random_base32(24).unwrap();
/// assert_eq!(s.len(), 24);
/// ```
pub fn random_base32(chars: usize) -> io::Result<String> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let byte_count = (chars * 5).div_ceil(8);
    let mut buf = vec![0u8; byte_count.max(1)];
    fill_bytes(&mut buf)?;
    let mut out = String::with_capacity(chars);
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut idx = 0;
    while out.len() < chars {
        if bits < 5 {
            acc |= (buf[idx] as u64) << bits;
            bits += 8;
            idx += 1;
            if idx == buf.len() && bits < 5 && out.len() < chars {
                // Should not happen with our byte_count math; guard
                // defensively rather than panic.
                let mut extra = [0u8; 8];
                fill_bytes(&mut extra)?;
                for &b in &extra {
                    acc |= (b as u64) << bits;
                    bits += 8;
                    if bits >= 5 + 56 {
                        break;
                    }
                }
            }
        }
        out.push(ALPHABET[(acc & 0x1F) as usize] as char);
        acc >>= 5;
        bits -= 5;
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
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn empty_buffer_succeeds_without_syscall() {
        let mut buf: [u8; 0] = [];
        fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn random_u64_nonzero_majority() {
        // A single u64 is 0 with probability 2^-64 — observing it
        // even once in any reasonable test run indicates a bug.
        let n = random_u64().unwrap();
        // We can't strictly assert != 0 without a 2^-64 false-failure
        // chance, but successive draws being equal is overwhelmingly
        // unlikely. Verify two draws differ.
        let m = random_u64().unwrap();
        assert_ne!(n, m, "two u64 draws should differ");
    }

    #[test]
    fn random_u32_two_draws_differ() {
        let a = random_u32().unwrap();
        let b = random_u32().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn random_hex_correct_length_and_alphabet() {
        let h = random_hex(16).unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(h.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn random_hex_zero_length() {
        let h = random_hex(0).unwrap();
        assert_eq!(h, "");
    }

    #[test]
    fn random_base32_correct_length_and_alphabet() {
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        for len in [1, 5, 8, 16, 24, 32, 64] {
            let s = random_base32(len).unwrap();
            assert_eq!(s.len(), len, "length {len}");
            assert!(
                s.bytes().all(|b| ALPHABET.contains(&b)),
                "alphabet violation in {s}"
            );
        }
    }

    #[test]
    fn random_bytes_is_correct_length() {
        let b = random_bytes(48).unwrap();
        assert_eq!(b.len(), 48);
    }

    #[test]
    fn large_buffer_fill_succeeds() {
        // A buffer larger than macOS's 256-byte getentropy cap and
        // larger than typical syscall short-read thresholds. Verifies
        // the looping/chunking logic on every platform.
        let mut buf = vec![0u8; 4096];
        fill_bytes(&mut buf).unwrap();
        // The probability all 4096 bytes are zero is 2^-32768 — any
        // observation of that is a bug.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn stress_many_small_calls() {
        // 1000 calls of 32 bytes each. Exercises syscall stability.
        for _ in 0..1000 {
            let mut buf = [0u8; 32];
            fill_bytes(&mut buf).unwrap();
        }
    }

    #[test]
    fn byte_frequency_chi_squared() {
        // 1 048 576 bytes — 256 buckets, expected ~4096 per bucket.
        // Chi-squared critical value (255 d.f., alpha = 0.001) is
        // about 330. We use 500 to keep flake rate negligible.
        let mut buf = vec![0u8; 1 << 20];
        fill_bytes(&mut buf).unwrap();

        let mut counts = [0u32; 256];
        for &b in &buf {
            counts[b as usize] += 1;
        }
        let n = buf.len() as f64;
        let expected = n / 256.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 500.0, "byte-frequency chi-squared {chi} too high");
    }
}
