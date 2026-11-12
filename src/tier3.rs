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
//! On Linux, `getrandom` returns `ENOSYS` in two different cases: the
//! kernel is older than 3.17 and does not have the syscall, or a
//! sandbox (a seccomp filter, some container runtimes) blocks it and
//! reports `ENOSYS`. Since 1.1.0 the two are told apart by the kernel
//! version from `uname(2)`:
//!
//! - kernel older than 3.17: the syscall does not exist, and the
//!   implementation reads `/dev/urandom` instead for the rest of the
//!   process. On these kernels `/dev/urandom` does not wait for the
//!   entropy pool to be initialised at early boot.
//! - kernel 3.17 or newer, or a version that cannot be read: the
//!   syscall exists and was blocked, so the call returns the `ENOSYS`
//!   error. It does not switch to another source behind the sandbox's
//!   back.
//!
//! It is never used as a fallback from a *failed* syscall, only from
//! an *unavailable* one.
//!
//! On every platform, if the OS RNG cannot service the request, the
//! call returns `io::Error`. This module will **never** fall back to
//! a non-cryptographic source.
//!
//! ## Failure modes
//!
//! - On sandboxed processes (Linux seccomp, macOS sandbox) where the
//!   syscall is filtered, you receive `io::Error`, whether the filter
//!   reports `EPERM` or `ENOSYS`.
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
//! One syscall worth of overhead per call (typically 100 to 500 ns).
//! The string functions and [`shuffle`] read up to 256 bytes per
//! syscall and draw every character or swap from that, so a 32
//! character token costs one syscall. Nothing is kept between calls:
//! the buffer lives on the stack for one call only, so the module
//! stays safe across `fork()` and VM snapshots.

use core::ops::{Range, RangeInclusive};
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
        #[cfg(test)]
        super::test_counter::bump();
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
            fn uname(buf: *mut UtsName) -> i32;
        }

        /// `struct utsname` as glibc and musl define it on Linux: six
        /// NUL-terminated fields of 65 bytes each.
        #[repr(C)]
        struct UtsName {
            sysname: [u8; 65],
            nodename: [u8; 65],
            release: [u8; 65],
            version: [u8; 65],
            machine: [u8; 65],
            domainname: [u8; 65],
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
                    if !kernel_lacks_getrandom() {
                        // The kernel has the syscall, so something
                        // (a seccomp filter, a sandbox) blocked it.
                        // Report that instead of switching sources.
                        return Err(io::Error::from_raw_os_error(e));
                    }
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

        /// True only when the running kernel is known to predate
        /// `getrandom(2)` (added in Linux 3.17). An unreadable version
        /// counts as "has it", so `ENOSYS` is then reported as an error.
        fn kernel_lacks_getrandom() -> bool {
            let mut uts = UtsName {
                sysname: [0; 65],
                nodename: [0; 65],
                release: [0; 65],
                version: [0; 65],
                machine: [0; 65],
                domainname: [0; 65],
            };
            // SAFETY: `uts` is a valid, writable `struct utsname` with
            // the layout glibc and musl use on Linux.
            if unsafe { uname(&mut uts) } != 0 {
                return false;
            }
            match super::super::parse_kernel_version(&uts.release) {
                Some(v) => v < (3, 17),
                None => false,
            }
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

/// Parse the `major.minor` prefix of a NUL-terminated kernel release
/// string such as `5.15.0-91-generic`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_kernel_version(release: &[u8]) -> Option<(u32, u32)> {
    let end = release
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(release.len());
    let s = core::str::from_utf8(&release[..end]).ok()?;
    let mut parts = s.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Number of OS reads made on this thread, for tests of batching.
#[cfg(test)]
mod test_counter {
    use std::cell::Cell;

    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn bump() {
        CALLS.with(|c| c.set(c.get() + 1));
    }

    pub(super) fn take() -> usize {
        CALLS.with(|c| c.replace(0))
    }
}

/// Random `u64` words read from the OS in batches, for one call.
///
/// Reads at most 32 words per syscall, and only as many as
/// the caller said it needs (plus a refill on the rare rejection).
/// Lives on the stack for one public call; nothing is kept afterwards.
const WORDS_MAX: usize = 32;

struct Words {
    buf: [u8; WORDS_MAX * 8],
    pos: usize,
    len: usize,
    remaining: usize,
}

impl Words {
    /// A source for about `needed` words.
    fn new(needed: usize) -> Self {
        Self {
            buf: [0; WORDS_MAX * 8],
            pos: 0,
            len: 0,
            remaining: needed,
        }
    }

    fn next(&mut self) -> io::Result<u64> {
        if self.pos == self.len {
            let words = self.remaining.clamp(1, WORDS_MAX);
            let bytes = words * 8;
            fill_bytes(&mut self.buf[..bytes])?;
            self.pos = 0;
            self.len = bytes;
        }
        let mut w = [0u8; 8];
        w.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.buf[self.pos..self.pos + 8].fill(0);
        self.pos += 8;
        self.remaining = self.remaining.saturating_sub(1);
        Ok(u64::from_le_bytes(w))
    }

    /// Uniform value in `[0, n)` by Lemire's method. `n > 0`.
    fn bounded(&mut self, n: u64) -> io::Result<u64> {
        debug_assert!(n != 0, "Words::bounded requires n > 0");
        let mut m: u128 = (self.next()? as u128).wrapping_mul(n as u128);
        let mut l: u64 = m as u64;
        if l < n {
            let t: u64 = n.wrapping_neg() % n;
            while l < t {
                m = (self.next()? as u128).wrapping_mul(n as u128);
                l = m as u64;
            }
        }
        Ok((m >> 64) as u64)
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

// ------------------------------------------------------------
// Bounded-range API
//
// Every bounded function below pulls a fresh `u64` from the OS CSPRNG
// and reduces it with Lemire's "Nearly Divisionless" rejection
// sampling. The result is uniformly distributed over the requested
// range with no modulo bias.
//
// Each rejected draw is a fresh syscall (or a fresh `/dev/urandom`
// read on the Linux ENOSYS fallback path). The rejection rate is
// approximately `n / 2^64` per draw, so for any range smaller than
// half the u64 space, the expected syscall count per call is
// effectively 1.
//
// Invalid ranges (empty / reversed) return
// `io::Error` with `ErrorKind::InvalidInput` rather than panicking,
// matching the rest of the Tier 3 fallible API.
// ------------------------------------------------------------

/// Produce a uniformly-distributed `u64` in `[0, n)`.
///
/// Internal helper. `n` MUST be greater than zero; the public wrappers
/// enforce this. Returns `io::Error` only if the underlying
/// `random_u64()` call fails.
#[inline]
fn bounded_u64(n: u64) -> io::Result<u64> {
    debug_assert!(n != 0, "bounded_u64 requires n > 0");
    let mut x = random_u64()?;
    let mut m: u128 = (x as u128).wrapping_mul(n as u128);
    let mut l: u64 = m as u64;
    if l < n {
        let t: u64 = n.wrapping_neg() % n;
        while l < t {
            x = random_u64()?;
            m = (x as u128).wrapping_mul(n as u128);
            l = m as u64;
        }
    }
    Ok((m >> 64) as u64)
}

/// Helper: build an `InvalidInput` error for empty ranges.
#[inline]
fn empty_range_error(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Generate a cryptographically-secure uniformly-distributed `u64` in
/// the half-open range `[range.start, range.end)`.
///
/// Uses Lemire's "Nearly Divisionless" rejection sampling so the
/// output is genuinely uniform — there is no modulo bias.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty (`range.start >= range.end`).
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let n = tier3::random_range_u64(10..20)?;
/// assert!((10..20).contains(&n));
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn random_range_u64(range: Range<u64>) -> io::Result<u64> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_u64: empty range"));
    }
    let span = end - start;
    Ok(start + bounded_u64(span)?)
}

/// Generate a cryptographically-secure uniformly-distributed `u64` in
/// the closed range `[range.start(), range.end()]`.
///
/// The full-width inclusive range `0..=u64::MAX` is supported and is
/// equivalent to a raw `random_u64()` call.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty (`*range.start() > *range.end()`).
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let d = tier3::random_range_inclusive_u64(1..=6)?;
/// assert!((1..=6).contains(&d));
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn random_range_inclusive_u64(range: RangeInclusive<u64>) -> io::Result<u64> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_u64: empty range"));
    }
    if start == 0 && end == u64::MAX {
        return random_u64();
    }
    let span = end - start + 1;
    Ok(start + bounded_u64(span)?)
}

/// Generate a cryptographically-secure uniformly-distributed `u32` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let pct = tier3::random_range_u32(0..100)?;
/// assert!(pct < 100);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn random_range_u32(range: Range<u32>) -> io::Result<u32> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_u32: empty range"));
    }
    let span = (end - start) as u64;
    Ok((start as u64 + bounded_u64(span)?) as u32)
}

/// Generate a cryptographically-secure uniformly-distributed `u32` in
/// the closed range `[range.start(), range.end()]`.
///
/// The full-width inclusive range `0..=u32::MAX` is supported.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
pub fn random_range_inclusive_u32(range: RangeInclusive<u32>) -> io::Result<u32> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_u32: empty range"));
    }
    let span = (end as u64) - (start as u64) + 1;
    Ok((start as u64 + bounded_u64(span)?) as u32)
}

/// Generate a cryptographically-secure uniformly-distributed `i64` in
/// the half-open range `[range.start, range.end)`.
///
/// Negative bounds and mixed-sign ranges are supported.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
///
/// let n = tier3::random_range_i64(-50..50)?;
/// assert!((-50..50).contains(&n));
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn random_range_i64(range: Range<i64>) -> io::Result<i64> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_i64: empty range"));
    }
    let span = (end as i128 - start as i128) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i128) + (offset as i128)) as i64)
}

/// Generate a cryptographically-secure uniformly-distributed `i64` in
/// the closed range `[range.start(), range.end()]`.
///
/// The full-width inclusive range `i64::MIN..=i64::MAX` is supported
/// and is equivalent to reinterpreting a raw `random_u64()` draw as
/// `i64`.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
pub fn random_range_inclusive_i64(range: RangeInclusive<i64>) -> io::Result<i64> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_i64: empty range"));
    }
    if start == i64::MIN && end == i64::MAX {
        return random_u64().map(|u| u as i64);
    }
    let span = ((end as i128) - (start as i128) + 1) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i128) + (offset as i128)) as i64)
}

/// Generate a cryptographically-secure uniformly-distributed `i32` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
pub fn random_range_i32(range: Range<i32>) -> io::Result<i32> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_i32: empty range"));
    }
    let span = (end as i64 - start as i64) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i64) + (offset as i64)) as i32)
}

/// Generate a cryptographically-secure uniformly-distributed `i32` in
/// the closed range `[range.start(), range.end()]`.
///
/// The full-width inclusive range `i32::MIN..=i32::MAX` is supported.
///
/// # Errors
///
/// - Returns `io::Error` with `ErrorKind::InvalidInput` if the range
///   is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
pub fn random_range_inclusive_i32(range: RangeInclusive<i32>) -> io::Result<i32> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_i32: empty range"));
    }
    let span = ((end as i64) - (start as i64) + 1) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i64) + (offset as i64)) as i32)
}

// ------------------------------------------------------------
// Bounded-range API — additional integer widths
// ------------------------------------------------------------

/// Produce a uniformly-distributed `u128` in `[0, n)`.
///
/// Internal helper. Lemire's "Nearly Divisionless" rejection sampling
/// generalised to 128-bit width via a 256-bit intermediate. Two
/// `random_u64` calls (two syscalls) per draw in the common case.
#[inline]
fn bounded_u128(n: u128) -> io::Result<u128> {
    debug_assert!(n != 0, "bounded_u128 requires n > 0");
    let mut x = draw_u128()?;
    let (mut hi, mut lo) = mul_128_full(x, n);
    if lo < n {
        let t: u128 = n.wrapping_neg() % n;
        while lo < t {
            x = draw_u128()?;
            let (h, l) = mul_128_full(x, n);
            hi = h;
            lo = l;
        }
    }
    let _ = x;
    Ok(hi)
}

#[inline]
fn draw_u128() -> io::Result<u128> {
    let mut buf = [0u8; 16];
    fill_bytes(&mut buf)?;
    Ok(u128::from_le_bytes(buf))
}

#[inline]
fn mul_128_full(a: u128, b: u128) -> (u128, u128) {
    let a_lo: u64 = a as u64;
    let a_hi: u64 = (a >> 64) as u64;
    let b_lo: u64 = b as u64;
    let b_hi: u64 = (b >> 64) as u64;
    let p00: u128 = (a_lo as u128) * (b_lo as u128);
    let p01: u128 = (a_lo as u128) * (b_hi as u128);
    let p10: u128 = (a_hi as u128) * (b_lo as u128);
    let p11: u128 = (a_hi as u128) * (b_hi as u128);
    let mask_lo: u128 = 0xFFFF_FFFF_FFFF_FFFF;
    let mid: u128 = (p00 >> 64) + (p01 & mask_lo) + (p10 & mask_lo);
    let low: u128 = (p00 & mask_lo) | (mid << 64);
    let high: u128 = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

/// Generate a cryptographically-secure uniformly-distributed `u8` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// - Returns `InvalidInput` if the range is empty.
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
/// let n = tier3::random_range_u8(0..100)?;
/// assert!(n < 100);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn random_range_u8(range: Range<u8>) -> io::Result<u8> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_u8: empty range"));
    }
    let span = (end - start) as u64;
    Ok((start as u64 + bounded_u64(span)?) as u8)
}

/// Generate a cryptographically-secure uniformly-distributed `u8` in
/// the closed range `[range.start(), range.end()]`. The full-width
/// `0..=u8::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_u8(range: RangeInclusive<u8>) -> io::Result<u8> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_u8: empty range"));
    }
    let span = (end as u64) - (start as u64) + 1;
    Ok((start as u64 + bounded_u64(span)?) as u8)
}

/// Generate a cryptographically-secure uniformly-distributed `u16` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_u16(range: Range<u16>) -> io::Result<u16> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_u16: empty range"));
    }
    let span = (end - start) as u64;
    Ok((start as u64 + bounded_u64(span)?) as u16)
}

/// Generate a cryptographically-secure uniformly-distributed `u16` in
/// the closed range `[range.start(), range.end()]`. The full-width
/// `0..=u16::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_u16(range: RangeInclusive<u16>) -> io::Result<u16> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_u16: empty range"));
    }
    let span = (end as u64) - (start as u64) + 1;
    Ok((start as u64 + bounded_u64(span)?) as u16)
}

/// Generate a cryptographically-secure uniformly-distributed `u128` in
/// the half-open range `[range.start, range.end)`.
///
/// Uses two `random_u64` calls per draw in the common case. Lemire
/// rejection sampling at 128-bit width via a 256-bit intermediate.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_u128(range: Range<u128>) -> io::Result<u128> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_u128: empty range"));
    }
    let span = end - start;
    Ok(start + bounded_u128(span)?)
}

/// Generate a cryptographically-secure uniformly-distributed `u128` in
/// the closed range `[range.start(), range.end()]`. The full-width
/// `0..=u128::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_u128(range: RangeInclusive<u128>) -> io::Result<u128> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error(
            "random_range_inclusive_u128: empty range",
        ));
    }
    if start == 0 && end == u128::MAX {
        return draw_u128();
    }
    let span = end - start + 1;
    Ok(start + bounded_u128(span)?)
}

/// Generate a cryptographically-secure uniformly-distributed `usize`
/// in the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_usize(range: Range<usize>) -> io::Result<usize> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_usize: empty range"));
    }
    let span = (end - start) as u64;
    Ok((start as u64 + bounded_u64(span)?) as usize)
}

/// Generate a cryptographically-secure uniformly-distributed `usize`
/// in the closed range `[range.start(), range.end()]`. The full-width
/// `0..=usize::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_usize(range: RangeInclusive<usize>) -> io::Result<usize> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error(
            "random_range_inclusive_usize: empty range",
        ));
    }
    if start == 0 && end == usize::MAX {
        #[cfg(target_pointer_width = "64")]
        {
            return random_u64().map(|u| u as usize);
        }
        #[cfg(not(target_pointer_width = "64"))]
        {
            let span = (end as u64) - (start as u64) + 1;
            return bounded_u64(span).map(|o| (start as u64 + o) as usize);
        }
    }
    let span = (end - start) as u64 + 1;
    Ok((start as u64 + bounded_u64(span)?) as usize)
}

/// Generate a cryptographically-secure uniformly-distributed `i8` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_i8(range: Range<i8>) -> io::Result<i8> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_i8: empty range"));
    }
    let span = (end as i64 - start as i64) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i64) + (offset as i64)) as i8)
}

/// Generate a cryptographically-secure uniformly-distributed `i8` in
/// the closed range `[range.start(), range.end()]`. The full-width
/// `i8::MIN..=i8::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_i8(range: RangeInclusive<i8>) -> io::Result<i8> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_i8: empty range"));
    }
    let span = ((end as i64) - (start as i64) + 1) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i64) + (offset as i64)) as i8)
}

/// Generate a cryptographically-secure uniformly-distributed `i16` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_i16(range: Range<i16>) -> io::Result<i16> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_i16: empty range"));
    }
    let span = (end as i64 - start as i64) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i64) + (offset as i64)) as i16)
}

/// Generate a cryptographically-secure uniformly-distributed `i16` in
/// the closed range `[range.start(), range.end()]`. The full-width
/// `i16::MIN..=i16::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_i16(range: RangeInclusive<i16>) -> io::Result<i16> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error("random_range_inclusive_i16: empty range"));
    }
    let span = ((end as i64) - (start as i64) + 1) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i64) + (offset as i64)) as i16)
}

/// Generate a cryptographically-secure uniformly-distributed `i128` in
/// the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_i128(range: Range<i128>) -> io::Result<i128> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_i128: empty range"));
    }
    let span = (end as u128).wrapping_sub(start as u128);
    let offset = bounded_u128(span)?;
    Ok((start as u128).wrapping_add(offset) as i128)
}

/// Generate a cryptographically-secure uniformly-distributed `i128` in
/// the closed range `[range.start(), range.end()]`. The full-width
/// `i128::MIN..=i128::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_i128(range: RangeInclusive<i128>) -> io::Result<i128> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error(
            "random_range_inclusive_i128: empty range",
        ));
    }
    if start == i128::MIN && end == i128::MAX {
        return draw_u128().map(|u| u as i128);
    }
    let span = (end as u128).wrapping_sub(start as u128) + 1;
    let offset = bounded_u128(span)?;
    Ok((start as u128).wrapping_add(offset) as i128)
}

/// Generate a cryptographically-secure uniformly-distributed `isize`
/// in the half-open range `[range.start, range.end)`.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_isize(range: Range<isize>) -> io::Result<isize> {
    let Range { start, end } = range;
    if start >= end {
        return Err(empty_range_error("random_range_isize: empty range"));
    }
    let span = (end as i128 - start as i128) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i128) + (offset as i128)) as isize)
}

/// Generate a cryptographically-secure uniformly-distributed `isize`
/// in the closed range `[range.start(), range.end()]`. The full-width
/// `isize::MIN..=isize::MAX` is supported.
///
/// # Errors
///
/// As for [`random_range_u8`].
pub fn random_range_inclusive_isize(range: RangeInclusive<isize>) -> io::Result<isize> {
    let (start, end) = range.into_inner();
    if start > end {
        return Err(empty_range_error(
            "random_range_inclusive_isize: empty range",
        ));
    }
    if start == isize::MIN && end == isize::MAX {
        #[cfg(target_pointer_width = "64")]
        {
            return random_u64().map(|u| u as isize);
        }
        #[cfg(not(target_pointer_width = "64"))]
        {
            let span = ((end as i128) - (start as i128) + 1) as u64;
            let offset = bounded_u64(span)?;
            return Ok(((start as i128) + (offset as i128)) as isize);
        }
    }
    let span = ((end as i128) - (start as i128) + 1) as u64;
    let offset = bounded_u64(span)?;
    Ok(((start as i128) + (offset as i128)) as isize)
}

// ------------------------------------------------------------
// String generation
// ------------------------------------------------------------

/// Helper: build an `InvalidInput` error for charset-validation
/// failures.
#[inline]
fn invalid_charset_error(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Generate a cryptographically-secure random string of exactly `len`
/// characters drawn from `charset` (uniformly).
///
/// Selection uses Lemire rejection sampling against `charset.len()`,
/// so the per-character distribution is uniform — no modulo bias.
///
/// Random words are read from the OS up to 256 bytes per syscall, so
/// a string of up to 32 characters usually costs one syscall.
///
/// # Errors
///
/// - Returns `InvalidInput` if `charset` is empty or contains a
///   non-ASCII byte (byte >= 128).
/// - Returns `io::Error` if the OS CSPRNG is unavailable.
///
/// # Example
///
/// ```
/// use mod_rand::{tier3, charsets};
/// let s = tier3::random_string(16, charsets::ALPHANUMERIC)?;
/// assert_eq!(s.len(), 16);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn random_string(len: usize, charset: &[u8]) -> io::Result<String> {
    if charset.is_empty() {
        return Err(invalid_charset_error(
            "random_string: charset must be non-empty",
        ));
    }
    if !charset.iter().all(|&b| b < 128) {
        return Err(invalid_charset_error(
            "random_string: charset must be ASCII (every byte < 128)",
        ));
    }
    let n = charset.len() as u64;
    let mut out = String::with_capacity(len);
    let mut words = Words::new(len);
    for _ in 0..len {
        let idx = words.bounded(n)? as usize;
        out.push(charset[idx] as char);
    }
    Ok(out)
}

/// Generate a cryptographically-secure ASCII alphanumeric string
/// (`A-Z`, `a-z`, `0-9`) of exactly `len` characters.
///
/// Equivalent to `random_string(len, charsets::ALPHANUMERIC)`.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
/// let token = tier3::random_alphanumeric(32)?;
/// assert_eq!(token.len(), 32);
/// # Ok::<(), std::io::Error>(())
/// ```
#[inline]
pub fn random_alphanumeric(len: usize) -> io::Result<String> {
    random_string(len, crate::charsets::ALPHANUMERIC)
}

/// Generate a cryptographically-secure ASCII alphabetic string
/// (`A-Z`, `a-z`) of exactly `len` characters.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
/// let s = tier3::random_alpha(12)?;
/// assert_eq!(s.len(), 12);
/// # Ok::<(), std::io::Error>(())
/// ```
#[inline]
pub fn random_alpha(len: usize) -> io::Result<String> {
    random_string(len, crate::charsets::ALPHA)
}

/// Generate a cryptographically-secure ASCII numeric string (`0-9`)
/// of exactly `len` characters. Leading zeros may appear.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
/// let s = tier3::random_numeric(6)?;
/// assert_eq!(s.len(), 6);
/// # Ok::<(), std::io::Error>(())
/// ```
#[inline]
pub fn random_numeric(len: usize) -> io::Result<String> {
    random_string(len, crate::charsets::NUMERIC)
}

/// Generate a cryptographically-secure lowercase hex string (`0-9`,
/// `a-f`) of exactly `len` characters.
///
/// **Distinct from [`random_hex`]**: [`random_hex`] takes a byte
/// count and returns `bytes * 2` hex characters; this function takes
/// a character count directly. Both produce identical entropy per
/// character but accept different argument units.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
/// let s = tier3::random_hex_string(40)?;
/// assert_eq!(s.len(), 40);
/// # Ok::<(), std::io::Error>(())
/// ```
#[inline]
pub fn random_hex_string(len: usize) -> io::Result<String> {
    random_string(len, crate::charsets::HEX_LOWER)
}

// ------------------------------------------------------------
// Collection operations — cryptographic shuffle
// ------------------------------------------------------------

/// In-place cryptographically-secure uniform Fisher-Yates shuffle.
///
/// Every permutation of `slice` is equally likely under the OS
/// CSPRNG. O(n) time, no allocation. Each swap consumes one
/// `random_u64` worth of entropy from Tier 3; the words are read up to
/// 32 at a time, so a 52-card deck costs two syscalls.
///
/// # Errors
///
/// Returns `io::Error` if the OS CSPRNG is unavailable. If the call
/// fails mid-shuffle, the slice is left in a partially-shuffled state
/// but still contains exactly its original elements.
///
/// # Example
///
/// ```
/// use mod_rand::tier3;
/// let mut deck: Vec<u8> = (0..52).collect();
/// tier3::shuffle(&mut deck)?;
/// // deck is now a uniformly-random permutation.
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn shuffle<T>(slice: &mut [T]) -> io::Result<()> {
    let n = slice.len();
    if n < 2 {
        return Ok(());
    }
    let mut words = Words::new(n - 1);
    for i in (1..n).rev() {
        // Pick j uniformly in [0, i]. i fits in u64 because n <= usize::MAX
        // and usize <= u64 on every supported target.
        let span = (i as u64) + 1;
        let j = words.bounded(span)? as usize;
        slice.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn strings_and_shuffle_batch_os_reads() {
        let _ = test_counter::take();
        let t = random_alphanumeric(32).unwrap();
        assert_eq!(t.len(), 32);
        assert_eq!(test_counter::take(), 1, "32 characters, one OS read");

        let t = random_string(100, crate::charsets::HEX_LOWER).unwrap();
        assert_eq!(t.len(), 100);
        assert_eq!(test_counter::take(), 4, "100 characters, four OS reads");

        let mut deck: Vec<u8> = (0..52).collect();
        shuffle(&mut deck).unwrap();
        assert_eq!(test_counter::take(), 2, "51 swaps, two OS reads");
        let mut sorted = deck.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..52).collect::<Vec<u8>>());
    }

    #[test]
    fn words_bounded_is_in_range_and_uniform_enough() {
        let mut w = Words::new(60_000);
        let mut counts = [0u32; 6];
        for _ in 0..60_000 {
            let v = w.bounded(6).unwrap();
            counts[v as usize] += 1;
        }
        for c in counts {
            assert!((9_000..=11_000).contains(&c), "count {c} out of band");
        }
    }

    #[test]
    fn kernel_version_parsing() {
        assert_eq!(
            parse_kernel_version(b"5.15.0-91-generic\0\0"),
            Some((5, 15))
        );
        assert_eq!(
            parse_kernel_version(b"5.15.167.4-microsoft-standard-WSL2\0"),
            Some((5, 15))
        );
        assert_eq!(parse_kernel_version(b"3.16.0\0"), Some((3, 16)));
        assert_eq!(parse_kernel_version(b"3.17\0"), Some((3, 17)));
        assert_eq!(parse_kernel_version(b"6.1"), Some((6, 1)));
        assert_eq!(parse_kernel_version(b"\0"), None);
        assert_eq!(parse_kernel_version(b"linux\0"), None);
        assert!(parse_kernel_version(b"3.16.0\0").unwrap() < (3, 17));
        assert!(parse_kernel_version(b"4.4.0\0").unwrap() >= (3, 17));
    }

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
    fn random_u64_varies_within_small_sample() {
        let mut seen = HashSet::with_capacity(16);
        for _ in 0..16 {
            seen.insert(random_u64().unwrap());
        }
        assert!(seen.len() > 1, "u64 output appears constant in sample");
    }

    #[test]
    fn random_u32_varies_within_small_sample() {
        let mut seen = HashSet::with_capacity(32);
        for _ in 0..32 {
            seen.insert(random_u32().unwrap());
        }
        assert!(seen.len() > 1, "u32 output appears constant in sample");
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

    // ------------------------------------------------------------
    // Bounded-range tests
    // ------------------------------------------------------------

    #[test]
    fn random_range_u64_bounds() {
        for _ in 0..1000 {
            let n = random_range_u64(100..200).unwrap();
            assert!((100..200).contains(&n));
        }
    }

    #[test]
    fn random_range_u64_single_value_window() {
        // [start, start+1) — every draw lands on start. No syscalls
        // wasted on rejection in this case (span=1, l=0 is never < n).
        for _ in 0..100 {
            assert_eq!(random_range_u64(7..8).unwrap(), 7);
        }
    }

    #[test]
    fn random_range_inclusive_u64_die_roll_visits_all_faces() {
        // 1000 cryptographic die rolls — all six faces must appear.
        let mut faces = [0u32; 6];
        for _ in 0..1000 {
            let d = random_range_inclusive_u64(1..=6).unwrap();
            assert!((1..=6).contains(&d));
            faces[(d - 1) as usize] += 1;
        }
        for (i, &c) in faces.iter().enumerate() {
            assert!(c > 0, "face {} never appeared in 1000 rolls", i + 1);
        }
    }

    #[test]
    fn random_range_inclusive_u64_single_value() {
        for _ in 0..100 {
            assert_eq!(random_range_inclusive_u64(42..=42).unwrap(), 42);
        }
    }

    #[test]
    fn random_range_inclusive_u64_full_width() {
        // 0..=u64::MAX — full-width path. Two draws differ.
        let a = random_range_inclusive_u64(0..=u64::MAX).unwrap();
        let b = random_range_inclusive_u64(0..=u64::MAX).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn random_range_u32_bounds() {
        for _ in 0..1000 {
            let n = random_range_u32(0..256).unwrap();
            assert!(n < 256);
        }
    }

    #[test]
    fn random_range_inclusive_u32_full_width() {
        for _ in 0..100 {
            let _ = random_range_inclusive_u32(0..=u32::MAX).unwrap();
        }
    }

    #[test]
    fn random_range_i64_negative() {
        for _ in 0..1000 {
            let n = random_range_i64(-100..-50).unwrap();
            assert!((-100..-50).contains(&n));
        }
    }

    #[test]
    fn random_range_i64_mixed_sign() {
        let mut saw_neg = false;
        let mut saw_pos = false;
        for _ in 0..1000 {
            let n = random_range_i64(-100..100).unwrap();
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
    fn random_range_inclusive_i64_full_width() {
        let _ = random_range_inclusive_i64(i64::MIN..=i64::MAX).unwrap();
    }

    #[test]
    fn random_range_i32_bounds() {
        for _ in 0..1000 {
            let n = random_range_i32(-1000..1000).unwrap();
            assert!((-1000..1000).contains(&n));
        }
    }

    #[test]
    fn random_range_inclusive_i32_full_width() {
        for _ in 0..100 {
            let _ = random_range_inclusive_i32(i32::MIN..=i32::MAX).unwrap();
        }
    }

    #[test]
    fn random_range_u64_empty_returns_invalid_input() {
        let err = random_range_u64(10..10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn random_range_u64_reverse_returns_invalid_input() {
        let err = random_range_u64(10..5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn random_range_inclusive_u64_reverse_returns_invalid_input() {
        let err = random_range_inclusive_u64(10..=5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn random_range_i64_reverse_returns_invalid_input() {
        let err = random_range_i64(5..-5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn random_range_uniformity_chi_squared() {
        // 50 000 cryptographic draws over 50 buckets. Expected count
        // per bucket: 1000. Chi-squared critical value (49 d.f.,
        // alpha=0.001) is ~85; we use 200 to keep flake rate
        // negligible. This is fewer draws than tier1/tier2 because
        // each draw is a syscall.
        let mut counts = [0u32; 50];
        for _ in 0..50_000 {
            let v = random_range_u32(0..50).unwrap();
            counts[v as usize] += 1;
        }
        let expected = 50_000.0 / 50.0;
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(
            chi < 200.0,
            "tier3 chi-squared {chi} too high — bounded-range output is biased"
        );
    }
}
