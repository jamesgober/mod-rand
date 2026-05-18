//! # Tier 1 — Fast deterministic PRNG
//!
//! Pseudorandom number generator suitable for simulation, test
//! fixtures, and non-security shuffling. Seedable so runs are
//! reproducible. **Not cryptographically secure** — outputs are
//! predictable given the seed.
//!
//! Algorithm: xoshiro256\*\* by Blackman & Vigna. State expansion from
//! a single `u64` is performed with splitmix64. See
//! <https://prng.di.unimi.it/xoshiro256starstar.c> for the canonical
//! reference.
//!
//! Performance: ~1 ns per `u64` on x86_64 (single rotation, multiply,
//! and a handful of xors per output).
//!
//! Available in `no_std`.
//!
//! ## Bounded ranges
//!
//! The `gen_range_*` family of methods produces uniformly-distributed
//! values within a caller-specified `Range` or `RangeInclusive`:
//!
//! ```
//! use mod_rand::tier1::Xoshiro256;
//!
//! let mut rng = Xoshiro256::seed_from_u64(42);
//!
//! // Half-open: [0, 100) — never returns 100.
//! let pct: u32 = rng.gen_range_u32(0..100);
//! assert!(pct < 100);
//!
//! // Inclusive: [1, 6] — die roll, can return 1, 2, 3, 4, 5, or 6.
//! let die: u32 = rng.gen_range_inclusive_u32(1..=6);
//! assert!((1..=6).contains(&die));
//! ```
//!
//! All bounded methods use Lemire's "Nearly Divisionless" rejection
//! sampling, so the output is genuinely uniform — no modulo bias.

use core::ops::{Range, RangeInclusive};

/// Golden-ratio increment used by splitmix64.
const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// Polynomial-jump constants for `jump()` — equivalent to 2^128 calls
/// to `next_u64()`. Sourced verbatim from the canonical reference.
const JUMP: [u64; 4] = [
    0x180E_C6D3_3CFD_0ABA,
    0xD5A6_1266_F0C9_392C,
    0xA958_2618_E03F_C9AA,
    0x39AB_DC45_29B1_661C,
];

/// Polynomial-jump constants for `long_jump()` — equivalent to 2^192
/// calls to `next_u64()`. Sourced verbatim from the canonical reference.
const LONG_JUMP: [u64; 4] = [
    0x76E1_5D3E_FEFD_CBBF,
    0xC500_4E44_1C52_2FB3,
    0x7771_0069_854E_E241,
    0x3910_9BB0_2ACB_E635,
];

/// xoshiro256\*\* — fast, statistically sound, deterministic PRNG.
///
/// 256 bits of state. Period of `2^256 - 1`. Passes the BigCrush test
/// battery. Seedable from a single `u64` via splitmix64 expansion.
///
/// # Example
///
/// ```
/// use mod_rand::tier1::Xoshiro256;
///
/// let mut rng = Xoshiro256::seed_from_u64(42);
/// let n: u64 = rng.next_u64();
/// # let _ = n;
/// ```
///
/// # Reproducibility
///
/// The output stream is fully determined by the seed. Two generators
/// constructed with the same seed produce identical streams forever:
///
/// ```
/// use mod_rand::tier1::Xoshiro256;
///
/// let mut a = Xoshiro256::seed_from_u64(2026);
/// let mut b = Xoshiro256::seed_from_u64(2026);
/// for _ in 0..1024 {
///     assert_eq!(a.next_u64(), b.next_u64());
/// }
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Xoshiro256 {
    state: [u64; 4],
}

impl Xoshiro256 {
    /// Construct a generator from a single 64-bit seed.
    ///
    /// The seed is expanded to 256 bits of internal state by running
    /// four rounds of splitmix64 — the seeding strategy recommended by
    /// the xoshiro authors. Any seed value, including zero, is
    /// accepted; splitmix64 cannot produce the all-zero state from a
    /// nonzero counter, and the counter starts at `seed + GAMMA`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(0);
    /// let _ = rng.next_u64();
    /// ```
    #[inline]
    pub fn seed_from_u64(seed: u64) -> Self {
        let mut x = seed;
        Self {
            state: [
                splitmix64(&mut x),
                splitmix64(&mut x),
                splitmix64(&mut x),
                splitmix64(&mut x),
            ],
        }
    }

    /// Construct a generator directly from a 256-bit state.
    ///
    /// The state MUST NOT be all zero — that is the single fixed point
    /// of the xoshiro256\*\* transition. This constructor returns
    /// `None` in that case.
    ///
    /// Prefer [`seed_from_u64`](Self::seed_from_u64) for most uses;
    /// this exists for cases where you have a pre-derived 256-bit seed
    /// (e.g., from a key-derivation function).
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let rng = Xoshiro256::from_state([1, 2, 3, 4]).unwrap();
    /// # let _ = rng;
    /// assert!(Xoshiro256::from_state([0; 4]).is_none());
    /// ```
    #[inline]
    pub fn from_state(state: [u64; 4]) -> Option<Self> {
        if state == [0; 4] {
            None
        } else {
            Some(Self { state })
        }
    }

    /// Return the current internal state.
    ///
    /// Useful for checkpointing a stream so it can be resumed later
    /// via [`from_state`](Self::from_state).
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(7);
    /// let _ = rng.next_u64();
    /// let snapshot = rng.state();
    /// let resumed = Xoshiro256::from_state(snapshot).unwrap();
    /// assert_eq!(rng, resumed);
    /// ```
    #[inline]
    pub fn state(&self) -> [u64; 4] {
        self.state
    }

    /// Produce the next 64-bit output.
    ///
    /// One call performs a single rotation, two multiplies, a shift,
    /// six xors, and one further rotation — about a nanosecond on
    /// modern x86_64.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.next_u64();
    /// # let _ = n;
    /// ```
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        // result = rotl(s[1] * 5, 7) * 9
        let result = self.state[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);

        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);

        result
    }

    /// Produce the next 32-bit output by discarding the low half of a
    /// 64-bit draw.
    ///
    /// The high bits of xoshiro256\*\* are slightly stronger than the
    /// low bits — taking the high 32 is the recommended way to obtain
    /// a 32-bit value.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n: u32 = rng.next_u32();
    /// # let _ = n;
    /// ```
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Produce a value uniformly in `[0.0, 1.0)`.
    ///
    /// Uses the upper 53 bits of a `u64` output — the standard way to
    /// obtain a uniform double-precision draw without modulo bias.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let f = rng.next_f64();
    /// assert!((0.0..1.0).contains(&f));
    /// ```
    #[inline]
    pub fn next_f64(&mut self) -> f64 {
        // 53 bits of mantissa precision. 1.0 / 2^53.
        (self.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }

    /// Fill the entire buffer with PRNG output.
    ///
    /// Equivalent to repeatedly calling [`next_u64`](Self::next_u64)
    /// and writing the little-endian bytes, but avoids the overhead of
    /// per-byte calls. The final partial chunk (1..7 bytes) is filled
    /// from a single fresh `u64`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let mut buf = [0u8; 32];
    /// rng.fill_bytes(&mut buf);
    /// ```
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut chunks = buf.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes);
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let bytes = self.next_u64().to_le_bytes();
            tail.copy_from_slice(&bytes[..tail.len()]);
        }
    }

    // ------------------------------------------------------------
    // Bounded-range API
    //
    // Every bounded method below is a thin wrapper around the
    // private `bounded_u64` helper, which implements Lemire's
    // "Nearly Divisionless" rejection sampling. Signed-integer
    // methods compute the span in u128 to avoid overflow at extreme
    // endpoints; the full-width inclusive range is special-cased.
    // ------------------------------------------------------------

    /// Generate a uniformly-distributed `u64` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// Uses Lemire's "Nearly Divisionless" rejection sampling so the
    /// output is genuinely uniform — there is no modulo bias.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty (`range.start >= range.end`).
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_u64(10..20);
    /// assert!((10..20).contains(&n));
    /// ```
    #[inline]
    pub fn gen_range_u64(&mut self, range: Range<u64>) -> u64 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_u64: empty range {start}..{end}");
        let span = end - start;
        start + self.bounded_u64(span)
    }

    /// Generate a uniformly-distributed `u64` in the closed range
    /// `[range.start(), range.end()]`.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty (`*range.start() > *range.end()`).
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let die = rng.gen_range_inclusive_u64(1..=6);
    /// assert!((1..=6).contains(&die));
    /// ```
    ///
    /// The full-width inclusive range `0..=u64::MAX` is supported and
    /// is equivalent to a single `next_u64()` draw.
    #[inline]
    pub fn gen_range_inclusive_u64(&mut self, range: RangeInclusive<u64>) -> u64 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_u64: empty range {start}..={end}"
        );
        if start == 0 && end == u64::MAX {
            // span = 2^64, which doesn't fit in u64. Use a raw draw.
            return self.next_u64();
        }
        let span = end - start + 1;
        start + self.bounded_u64(span)
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
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let pct = rng.gen_range_u32(0..100);
    /// assert!(pct < 100);
    /// ```
    #[inline]
    pub fn gen_range_u32(&mut self, range: Range<u32>) -> u32 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_u32: empty range {start}..{end}");
        let span = (end - start) as u64;
        (start as u64 + self.bounded_u64(span)) as u32
    }

    /// Generate a uniformly-distributed `u32` in the closed range
    /// `[range.start(), range.end()]`.
    ///
    /// The full-width inclusive range `0..=u32::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_inclusive_u32(1..=100);
    /// assert!((1..=100).contains(&n));
    /// ```
    #[inline]
    pub fn gen_range_inclusive_u32(&mut self, range: RangeInclusive<u32>) -> u32 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_u32: empty range {start}..={end}"
        );
        // span = end - start + 1 fits in u64 (max value is 2^32).
        let span = (end as u64) - (start as u64) + 1;
        (start as u64 + self.bounded_u64(span)) as u32
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
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_i64(-50..50);
    /// assert!((-50..50).contains(&n));
    /// ```
    #[inline]
    pub fn gen_range_i64(&mut self, range: Range<i64>) -> i64 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_i64: empty range {start}..{end}");
        // span as u64 — works because end - start (in i128) is positive
        // and fits in u64 for any valid i64 half-open range. Maximum
        // possible span is i64::MAX - i64::MIN = 2^64 - 1.
        let span = (end as i128 - start as i128) as u64;
        let offset = self.bounded_u64(span);
        ((start as i128) + (offset as i128)) as i64
    }

    /// Generate a uniformly-distributed `i64` in the closed range
    /// `[range.start(), range.end()]`.
    ///
    /// The full-width inclusive range `i64::MIN..=i64::MAX` is
    /// supported and is equivalent to reinterpreting a raw
    /// `next_u64()` draw as `i64`.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_inclusive_i64(-1..=1);
    /// assert!((-1..=1).contains(&n));
    /// ```
    #[inline]
    pub fn gen_range_inclusive_i64(&mut self, range: RangeInclusive<i64>) -> i64 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_i64: empty range {start}..={end}"
        );
        if start == i64::MIN && end == i64::MAX {
            // span = 2^64. Reinterpret a raw draw.
            return self.next_u64() as i64;
        }
        // span = (end - start + 1) computed in i128 to avoid overflow.
        let span = ((end as i128) - (start as i128) + 1) as u64;
        let offset = self.bounded_u64(span);
        ((start as i128) + (offset as i128)) as i64
    }

    /// Generate a uniformly-distributed `i32` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_i32(-10..10);
    /// assert!((-10..10).contains(&n));
    /// ```
    #[inline]
    pub fn gen_range_i32(&mut self, range: Range<i32>) -> i32 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_i32: empty range {start}..{end}");
        // span fits in u64 (max 2^32 - 1).
        let span = (end as i64 - start as i64) as u64;
        let offset = self.bounded_u64(span);
        ((start as i64) + (offset as i64)) as i32
    }

    /// Generate a uniformly-distributed `i32` in the closed range
    /// `[range.start(), range.end()]`.
    ///
    /// The full-width inclusive range `i32::MIN..=i32::MAX` is
    /// supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_inclusive_i32(-100..=100);
    /// assert!((-100..=100).contains(&n));
    /// ```
    #[inline]
    pub fn gen_range_inclusive_i32(&mut self, range: RangeInclusive<i32>) -> i32 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_i32: empty range {start}..={end}"
        );
        // span = (end - start + 1) fits in u64 (max 2^32).
        let span = ((end as i64) - (start as i64) + 1) as u64;
        let offset = self.bounded_u64(span);
        ((start as i64) + (offset as i64)) as i32
    }

    /// Generate a uniformly-distributed `f64` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// The implementation draws a uniform value in `[0.0, 1.0)` via
    /// [`next_f64`](Self::next_f64) and scales it linearly into the
    /// requested range. The returned value is guaranteed finite.
    ///
    /// # Panics
    ///
    /// Panics if either bound is non-finite (NaN or infinity), the
    /// range is empty (`start >= end`), or the span `end - start`
    /// overflows to infinity (e.g., `-f64::MAX..f64::MAX`).
    ///
    /// There is no `gen_range_inclusive_f64`: the probability of
    /// producing either endpoint exactly is zero for any reasonable
    /// range, so the half-open and inclusive versions are operationally
    /// identical.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let x = rng.gen_range_f64(-1.0..1.0);
    /// assert!((-1.0..1.0).contains(&x));
    /// ```
    #[inline]
    pub fn gen_range_f64(&mut self, range: Range<f64>) -> f64 {
        let Range { start, end } = range;
        assert!(
            start.is_finite() && end.is_finite(),
            "gen_range_f64: non-finite bounds {start}..{end}"
        );
        assert!(start < end, "gen_range_f64: empty range {start}..{end}");
        let span = end - start;
        assert!(
            span.is_finite(),
            "gen_range_f64: span {start}..{end} overflows to infinity; \
             split the range or use a smaller interval"
        );
        start + self.next_f64() * span
    }

    // ------------------------------------------------------------
    // Bounded-range API — additional integer widths
    //
    // Smaller widths (u8/u16/i8/i16 and usize/isize on 32- and
    // 64-bit targets) route through `bounded_u64`. The 128-bit widths
    // use a dedicated `bounded_u128` helper that runs Lemire's
    // algorithm against a 256-bit intermediate built from two u64
    // draws.
    // ------------------------------------------------------------

    /// Generate a uniformly-distributed `u8` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// Uses Lemire's "Nearly Divisionless" rejection sampling so the
    /// output is genuinely uniform — there is no modulo bias.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_u8(0..200);
    /// assert!(n < 200);
    /// ```
    #[inline]
    pub fn gen_range_u8(&mut self, range: Range<u8>) -> u8 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_u8: empty range {start}..{end}");
        let span = (end - start) as u64;
        (start as u64 + self.bounded_u64(span)) as u8
    }

    /// Generate a uniformly-distributed `u8` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `0..=u8::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let b = rng.gen_range_inclusive_u8(0..=u8::MAX);
    /// # let _ = b;
    /// ```
    #[inline]
    pub fn gen_range_inclusive_u8(&mut self, range: RangeInclusive<u8>) -> u8 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_u8: empty range {start}..={end}"
        );
        let span = (end as u64) - (start as u64) + 1;
        (start as u64 + self.bounded_u64(span)) as u8
    }

    /// Generate a uniformly-distributed `u16` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// Uses Lemire's "Nearly Divisionless" rejection sampling.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_u16(0..1000);
    /// assert!(n < 1000);
    /// ```
    #[inline]
    pub fn gen_range_u16(&mut self, range: Range<u16>) -> u16 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_u16: empty range {start}..{end}");
        let span = (end - start) as u64;
        (start as u64 + self.bounded_u64(span)) as u16
    }

    /// Generate a uniformly-distributed `u16` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `0..=u16::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_u16(&mut self, range: RangeInclusive<u16>) -> u16 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_u16: empty range {start}..={end}"
        );
        let span = (end as u64) - (start as u64) + 1;
        (start as u64 + self.bounded_u64(span)) as u16
    }

    /// Generate a uniformly-distributed `u128` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// Uses Lemire's "Nearly Divisionless" rejection sampling against a
    /// 256-bit intermediate, generalised to 128 bits. Two `next_u64`
    /// draws per call in the common case.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let n = rng.gen_range_u128(0..(u128::MAX / 2));
    /// assert!(n < u128::MAX / 2);
    /// ```
    #[inline]
    pub fn gen_range_u128(&mut self, range: Range<u128>) -> u128 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_u128: empty range {start}..{end}");
        let span = end - start;
        start + self.bounded_u128(span)
    }

    /// Generate a uniformly-distributed `u128` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `0..=u128::MAX` is supported and is equivalent to a raw 128-bit
    /// draw (two `next_u64` calls concatenated).
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_u128(&mut self, range: RangeInclusive<u128>) -> u128 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_u128: empty range {start}..={end}"
        );
        if start == 0 && end == u128::MAX {
            // span = 2^128, doesn't fit. Use a raw 128-bit draw.
            return ((self.next_u64() as u128) << 64) | (self.next_u64() as u128);
        }
        let span = end - start + 1;
        start + self.bounded_u128(span)
    }

    /// Generate a uniformly-distributed `usize` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// On every supported Rust target (16-, 32-, and 64-bit pointer
    /// widths), `usize` fits in `u64` and the draw routes through
    /// [`bounded_u64`](Self::bounded_u64).
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_usize(&mut self, range: Range<usize>) -> usize {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_usize: empty range {start}..{end}");
        let span = (end - start) as u64;
        (start as u64 + self.bounded_u64(span)) as usize
    }

    /// Generate a uniformly-distributed `usize` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `0..=usize::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_usize(&mut self, range: RangeInclusive<usize>) -> usize {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_usize: empty range {start}..={end}"
        );
        if start == 0 && end == usize::MAX {
            // On 64-bit targets the span would be 2^64; raw draw.
            // On 32-bit and below the conversion to u64 doesn't lose.
            #[cfg(target_pointer_width = "64")]
            {
                return self.next_u64() as usize;
            }
            #[cfg(not(target_pointer_width = "64"))]
            {
                let span = (end as u64) - (start as u64) + 1;
                return (start as u64 + self.bounded_u64(span)) as usize;
            }
        }
        let span = (end - start) as u64 + 1;
        (start as u64 + self.bounded_u64(span)) as usize
    }

    /// Generate a uniformly-distributed `i8` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_i8(&mut self, range: Range<i8>) -> i8 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_i8: empty range {start}..{end}");
        let span = (end as i64 - start as i64) as u64;
        let offset = self.bounded_u64(span);
        ((start as i64) + (offset as i64)) as i8
    }

    /// Generate a uniformly-distributed `i8` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `i8::MIN..=i8::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_i8(&mut self, range: RangeInclusive<i8>) -> i8 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_i8: empty range {start}..={end}"
        );
        let span = ((end as i64) - (start as i64) + 1) as u64;
        let offset = self.bounded_u64(span);
        ((start as i64) + (offset as i64)) as i8
    }

    /// Generate a uniformly-distributed `i16` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_i16(&mut self, range: Range<i16>) -> i16 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_i16: empty range {start}..{end}");
        let span = (end as i64 - start as i64) as u64;
        let offset = self.bounded_u64(span);
        ((start as i64) + (offset as i64)) as i16
    }

    /// Generate a uniformly-distributed `i16` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `i16::MIN..=i16::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_i16(&mut self, range: RangeInclusive<i16>) -> i16 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_i16: empty range {start}..={end}"
        );
        let span = ((end as i64) - (start as i64) + 1) as u64;
        let offset = self.bounded_u64(span);
        ((start as i64) + (offset as i64)) as i16
    }

    /// Generate a uniformly-distributed `i128` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// Negative and mixed-sign ranges are supported. Internally the
    /// span is computed in `i256` semantics (via two `u128` halves)
    /// then reduced with Lemire's algorithm at 128-bit width.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_i128(&mut self, range: Range<i128>) -> i128 {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_i128: empty range {start}..{end}");
        // (end - start) fits in u128 for any valid i128 half-open range.
        // We compute it via wrapping arithmetic at u128 width: when
        // viewed mod 2^128, the unsigned bit pattern of (end - start)
        // matches the unsigned span. (end as u128).wrapping_sub(start as u128)
        // is the canonical way to obtain the span without going through
        // a wider type.
        let span = (end as u128).wrapping_sub(start as u128);
        let offset = self.bounded_u128(span);
        (start as u128).wrapping_add(offset) as i128
    }

    /// Generate a uniformly-distributed `i128` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `i128::MIN..=i128::MAX` is supported and is equivalent to
    /// reinterpreting a raw 128-bit draw as `i128`.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_i128(&mut self, range: RangeInclusive<i128>) -> i128 {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_i128: empty range {start}..={end}"
        );
        if start == i128::MIN && end == i128::MAX {
            // span = 2^128, doesn't fit. Reinterpret a raw draw.
            let hi = self.next_u64() as u128;
            let lo = self.next_u64() as u128;
            return ((hi << 64) | lo) as i128;
        }
        // span = (end - start + 1) at u128 width; wrapping_sub gives
        // the unsigned distance, then +1 cannot overflow because we
        // ruled out the full-width case above.
        let span = (end as u128).wrapping_sub(start as u128) + 1;
        let offset = self.bounded_u128(span);
        (start as u128).wrapping_add(offset) as i128
    }

    /// Generate a uniformly-distributed `isize` in the half-open range
    /// `[range.start, range.end)`.
    ///
    /// On every supported Rust target (16-, 32-, and 64-bit pointer
    /// widths), the span fits in `u64` and the draw routes through
    /// [`bounded_u64`](Self::bounded_u64).
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_isize(&mut self, range: Range<isize>) -> isize {
        let Range { start, end } = range;
        assert!(start < end, "gen_range_isize: empty range {start}..{end}");
        let span = (end as i128 - start as i128) as u64;
        let offset = self.bounded_u64(span);
        ((start as i128) + (offset as i128)) as isize
    }

    /// Generate a uniformly-distributed `isize` in the closed range
    /// `[range.start(), range.end()]`. The full-width range
    /// `isize::MIN..=isize::MAX` is supported.
    ///
    /// # Panics
    ///
    /// Panics if the range is empty.
    #[inline]
    pub fn gen_range_inclusive_isize(&mut self, range: RangeInclusive<isize>) -> isize {
        let (start, end) = range.into_inner();
        assert!(
            start <= end,
            "gen_range_inclusive_isize: empty range {start}..={end}"
        );
        if start == isize::MIN && end == isize::MAX {
            #[cfg(target_pointer_width = "64")]
            {
                return self.next_u64() as isize;
            }
            #[cfg(not(target_pointer_width = "64"))]
            {
                let span = ((end as i128) - (start as i128) + 1) as u64;
                let offset = self.bounded_u64(span);
                return ((start as i128) + (offset as i128)) as isize;
            }
        }
        let span = ((end as i128) - (start as i128) + 1) as u64;
        let offset = self.bounded_u64(span);
        ((start as i128) + (offset as i128)) as isize
    }

    // ------------------------------------------------------------
    // Distribution helpers
    // ------------------------------------------------------------

    /// Produce a value uniformly in `[0.0, 1.0)`.
    ///
    /// Stable alias for [`next_f64`](Self::next_f64); both methods
    /// produce identical output. The `gen_*` name complements
    /// [`gen_range_f64`](Self::gen_range_f64) for callers who reason in
    /// `gen_*` terms; `next_f64` is also kept for symmetry with
    /// `next_u64` / `next_u32`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let f = rng.gen_f64();
    /// assert!((0.0..1.0).contains(&f));
    /// ```
    #[inline]
    pub fn gen_f64(&mut self) -> f64 {
        self.next_f64()
    }

    /// Produce a value uniformly in `[0.0, 1.0)` at single precision.
    ///
    /// Uses the upper 24 bits of a `next_u32` draw — the standard way
    /// to obtain a uniform `f32` in the unit interval without modulo
    /// bias.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let f = rng.gen_f32();
    /// assert!((0.0..1.0).contains(&f));
    /// ```
    #[inline]
    pub fn gen_f32(&mut self) -> f32 {
        // 24 bits of mantissa precision. 1.0 / 2^24.
        (self.next_u32() >> 8) as f32 * (1.0 / ((1u32 << 24) as f32))
    }

    /// Bernoulli trial — return `true` with probability `p`.
    ///
    /// # Panics
    ///
    /// Panics if `p` is non-finite (NaN, ±∞) or outside `[0.0, 1.0]`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// // Strictly less than 1.0 — biased trial.
    /// let outcome = rng.gen_bool(0.5);
    /// # let _ = outcome;
    /// ```
    #[inline]
    pub fn gen_bool(&mut self, p: f64) -> bool {
        assert!(
            p.is_finite() && (0.0..=1.0).contains(&p),
            "gen_bool: p={p} must be finite and in [0.0, 1.0]"
        );
        if p == 0.0 {
            return false;
        }
        if p == 1.0 {
            return true;
        }
        self.next_f64() < p
    }

    // ------------------------------------------------------------
    // String generation (gated on std for String allocation)
    // ------------------------------------------------------------

    /// Generate a random string of exactly `len` characters drawn from
    /// `charset` (uniformly).
    ///
    /// Selection is performed via [`bounded_u64`](Self::bounded_u64)
    /// against `charset.len()`, so the per-character distribution is
    /// genuinely uniform — no modulo bias.
    ///
    /// # Panics
    ///
    /// Panics if `charset` is empty or contains any non-ASCII byte
    /// (byte >= 128). The ASCII guard preserves UTF-8 validity of the
    /// returned `String`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// use mod_rand::charsets;
    ///
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let id = rng.gen_string(12, charsets::ALPHANUMERIC);
    /// assert_eq!(id.len(), 12);
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn gen_string(&mut self, len: usize, charset: &[u8]) -> String {
        assert!(!charset.is_empty(), "gen_string: charset must be non-empty");
        assert!(
            charset.iter().all(|&b| b < 128),
            "gen_string: charset must be ASCII (every byte < 128)"
        );
        let n = charset.len() as u64;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let idx = self.bounded_u64(n) as usize;
            out.push(charset[idx] as char);
        }
        out
    }

    /// Generate a random ASCII alphanumeric string (`A-Z`, `a-z`,
    /// `0-9`) of exactly `len` characters.
    ///
    /// Equivalent to `gen_string(len, charsets::ALPHANUMERIC)`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let s = rng.gen_alphanumeric(16);
    /// assert_eq!(s.len(), 16);
    /// assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn gen_alphanumeric(&mut self, len: usize) -> String {
        self.gen_string(len, crate::charsets::ALPHANUMERIC)
    }

    /// Generate a random ASCII alphabetic string (`A-Z`, `a-z`) of
    /// exactly `len` characters.
    ///
    /// Equivalent to `gen_string(len, charsets::ALPHA)`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let s = rng.gen_alpha(8);
    /// assert_eq!(s.len(), 8);
    /// assert!(s.chars().all(|c| c.is_ascii_alphabetic()));
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn gen_alpha(&mut self, len: usize) -> String {
        self.gen_string(len, crate::charsets::ALPHA)
    }

    /// Generate a random ASCII numeric string (`0-9`) of exactly `len`
    /// characters. Leading zeros may appear.
    ///
    /// Equivalent to `gen_string(len, charsets::NUMERIC)`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let s = rng.gen_numeric(6);
    /// assert_eq!(s.len(), 6);
    /// assert!(s.chars().all(|c| c.is_ascii_digit()));
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn gen_numeric(&mut self, len: usize) -> String {
        self.gen_string(len, crate::charsets::NUMERIC)
    }

    /// Generate a random lowercase hex string (`0-9`, `a-f`) of exactly
    /// `len` characters.
    ///
    /// Equivalent to `gen_string(len, charsets::HEX_LOWER)`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let s = rng.gen_hex(32);
    /// assert_eq!(s.len(), 32);
    /// assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn gen_hex(&mut self, len: usize) -> String {
        self.gen_string(len, crate::charsets::HEX_LOWER)
    }

    // ------------------------------------------------------------
    // Collection operations
    // ------------------------------------------------------------

    /// In-place uniform Fisher-Yates shuffle.
    ///
    /// Every permutation of `slice` is equally likely. O(n) time, no
    /// allocation. Available in `no_std` — the implementation does not
    /// touch the heap.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let mut v = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    /// rng.shuffle(&mut v);
    /// // v is some permutation of the original.
    /// assert_eq!(v.iter().sum::<i32>(), 55);
    /// ```
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        // Fisher-Yates: for i from n-1 down to 1, swap slice[i] with
        // slice[gen_range_inclusive_usize(0..=i)]. Each iteration uses
        // an unbiased Lemire draw, so the resulting permutation is
        // uniform over the n! permutations.
        let n = slice.len();
        if n < 2 {
            return;
        }
        for i in (1..n).rev() {
            let j = self.gen_range_inclusive_usize(0..=i);
            slice.swap(i, j);
        }
    }

    /// Draw `k` references uniformly without replacement from `slice`.
    ///
    /// Returns a `Vec<&T>` of exactly `k` references; order preserves
    /// the original slice order (selection-sampling). Each k-subset of
    /// `slice` is equally likely to be returned. O(n) time, allocates
    /// exactly `k` slots.
    ///
    /// Algorithm: Knuth Algorithm S (selection sampling, *TAOCP* Vol.
    /// 2 §3.4.2). One linear pass; for each element decide whether to
    /// include it based on the number of items still needed vs. items
    /// remaining.
    ///
    /// # Panics
    ///
    /// Panics if `k > slice.len()`.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let pool = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    /// let picks: Vec<&i32> = rng.sample(&pool, 3);
    /// assert_eq!(picks.len(), 3);
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn sample<'a, T>(&mut self, slice: &'a [T], k: usize) -> Vec<&'a T> {
        let n = slice.len();
        assert!(
            k <= n,
            "sample: k={k} exceeds slice length n={n}"
        );
        let mut out: Vec<&'a T> = Vec::with_capacity(k);
        if k == 0 {
            return out;
        }
        let mut remaining_needed = k as u64;
        let mut remaining_pool = n as u64;
        for item in slice {
            // Probability of selecting this item is remaining_needed
            // / remaining_pool. Draw a uniform u64 in [0, remaining_pool)
            // and select if it's < remaining_needed.
            let draw = self.bounded_u64(remaining_pool);
            if draw < remaining_needed {
                out.push(item);
                remaining_needed -= 1;
                if remaining_needed == 0 {
                    break;
                }
            }
            remaining_pool -= 1;
        }
        out
    }

    /// Choose one index from `weights` proportional to its weight.
    ///
    /// Returns `Some(i)` where the probability of choosing index `i`
    /// is `weights[i] / weights.iter().sum()`. Returns `None` if
    /// `weights` is empty or every weight is zero.
    ///
    /// O(weights.len()) per call: one cumulative-sum pass plus one
    /// uniform `gen_range_f64` draw. No allocation.
    ///
    /// # Panics
    ///
    /// Panics if any weight is negative, NaN, or non-finite. (`+∞`,
    /// `-∞`, and `NaN` all panic.)
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let weights = [1.0, 2.0, 3.0, 4.0];
    /// let i = rng.weighted_index(&weights).unwrap();
    /// assert!(i < 4);
    /// ```
    pub fn weighted_index(&mut self, weights: &[f64]) -> Option<usize> {
        if weights.is_empty() {
            return None;
        }
        let mut total = 0.0_f64;
        for (i, &w) in weights.iter().enumerate() {
            assert!(
                w.is_finite() && w >= 0.0,
                "weighted_index: weights[{i}]={w} must be finite and non-negative"
            );
            total += w;
        }
        if total <= 0.0 {
            return None;
        }
        // Draw a uniform value in [0, total) and find the first
        // cumulative bucket that contains it.
        let pick = self.next_f64() * total;
        let mut cumulative = 0.0_f64;
        for (i, &w) in weights.iter().enumerate() {
            cumulative += w;
            if pick < cumulative {
                return Some(i);
            }
        }
        // Floating-point accumulation rounding can occasionally leave
        // `pick` >= the final cumulative; map that to the last
        // nonzero-weight index.
        weights.iter().rposition(|&w| w > 0.0)
    }

    /// Choose one item from `items` proportional to its weight.
    ///
    /// Wrapper around [`weighted_index`](Self::weighted_index) that
    /// returns the referenced item. Returns `None` if `items` is empty,
    /// `weights` is empty, or every weight is zero.
    ///
    /// # Panics
    ///
    /// Panics if `items.len() != weights.len()` or if any weight is
    /// negative / NaN / non-finite.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    /// let mut rng = Xoshiro256::seed_from_u64(1);
    /// let items = ["common", "uncommon", "rare", "epic"];
    /// let weights = [70.0, 20.0, 8.0, 2.0];
    /// let pick = rng.weighted_choice(&items, &weights).unwrap();
    /// # let _ = pick;
    /// ```
    pub fn weighted_choice<'a, T>(
        &mut self,
        items: &'a [T],
        weights: &[f64],
    ) -> Option<&'a T> {
        assert_eq!(
            items.len(),
            weights.len(),
            "weighted_choice: items.len()={} != weights.len()={}",
            items.len(),
            weights.len()
        );
        self.weighted_index(weights).map(|i| &items[i])
    }

    /// Produce a uniformly-distributed `u128` in `[0, n)`.
    ///
    /// Internal helper. Generalises Lemire's "Nearly Divisionless"
    /// algorithm from 64-bit to 128-bit by computing the 256-bit
    /// product `x * n` and using the high 128 bits as the candidate,
    /// the low 128 bits for the rejection threshold check.
    ///
    /// Two `next_u64` draws per call in the common case. `n` MUST be
    /// greater than zero.
    #[inline]
    fn bounded_u128(&mut self, n: u128) -> u128 {
        debug_assert!(n != 0, "bounded_u128 requires n > 0");
        let mut x = self.draw_u128();
        let (mut hi, mut lo) = mul_128_full(x, n);
        if lo < n {
            // Threshold: (-n) mod n at u128 width.
            let t: u128 = n.wrapping_neg() % n;
            while lo < t {
                x = self.draw_u128();
                let (h, l) = mul_128_full(x, n);
                hi = h;
                lo = l;
            }
        }
        let _ = x;
        hi
    }

    /// Raw 128-bit draw: concatenate two `next_u64` outputs.
    #[inline]
    fn draw_u128(&mut self) -> u128 {
        ((self.next_u64() as u128) << 64) | (self.next_u64() as u128)
    }

    /// Produce a uniformly-distributed `u64` in `[0, n)`.
    ///
    /// Internal helper for the bounded-range API. Implements Daniel
    /// Lemire's "Nearly Divisionless" rejection sampling (J. ACM 2019),
    /// which is unbiased — every value in `[0, n)` is equally likely.
    ///
    /// The expected number of `next_u64()` calls is approximately
    /// `1 + n / 2^64`, which is effectively 1 for any range smaller
    /// than half the `u64` space.
    ///
    /// `n` MUST be greater than zero. Public methods enforce this
    /// before calling.
    #[inline]
    fn bounded_u64(&mut self, n: u64) -> u64 {
        debug_assert!(n != 0, "bounded_u64 requires n > 0");
        // Single fast path covers ~99.99% of calls: one draw, one
        // multiply, no division.
        let mut x = self.next_u64();
        let mut m: u128 = (x as u128).wrapping_mul(n as u128);
        let mut l: u64 = m as u64;
        if l < n {
            // Rejection threshold: (-n) mod n in u64 arithmetic.
            let t: u64 = n.wrapping_neg() % n;
            while l < t {
                x = self.next_u64();
                m = (x as u128).wrapping_mul(n as u128);
                l = m as u64;
            }
        }
        (m >> 64) as u64
    }

    /// Advance the state by 2^128 calls to [`next_u64`](Self::next_u64).
    ///
    /// Use this to obtain non-overlapping parallel streams: clone the
    /// generator, call `jump()` on the clone, and the clone now
    /// produces a stream that will not collide with the original for
    /// 2^128 outputs.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut a = Xoshiro256::seed_from_u64(1);
    /// let mut b = a.clone();
    /// b.jump();
    /// assert_ne!(a.next_u64(), b.next_u64());
    /// ```
    pub fn jump(&mut self) {
        self.apply_jump(&JUMP);
    }

    /// Advance the state by 2^192 calls to [`next_u64`](Self::next_u64).
    ///
    /// Use this to partition the period into 2^64 non-overlapping
    /// streams, each itself capable of 2^128 further [`jump`](Self::jump)
    /// substreams.
    ///
    /// # Example
    ///
    /// ```
    /// use mod_rand::tier1::Xoshiro256;
    ///
    /// let mut a = Xoshiro256::seed_from_u64(1);
    /// let mut b = a.clone();
    /// b.long_jump();
    /// assert_ne!(a.next_u64(), b.next_u64());
    /// ```
    pub fn long_jump(&mut self) {
        self.apply_jump(&LONG_JUMP);
    }

    fn apply_jump(&mut self, constants: &[u64; 4]) {
        let mut s0 = 0u64;
        let mut s1 = 0u64;
        let mut s2 = 0u64;
        let mut s3 = 0u64;

        for &word in constants {
            for b in 0..64 {
                if (word & (1u64 << b)) != 0 {
                    s0 ^= self.state[0];
                    s1 ^= self.state[1];
                    s2 ^= self.state[2];
                    s3 ^= self.state[3];
                }
                let _ = self.next_u64();
            }
        }

        self.state[0] = s0;
        self.state[1] = s1;
        self.state[2] = s2;
        self.state[3] = s3;
    }
}

/// Full 256-bit product of two `u128` values, returned as
/// `(high, low)` where each is a `u128` half of the 256-bit result.
///
/// Used by `bounded_u128` to implement Lemire's algorithm at 128-bit
/// width. Pure shifts and 64×64→128 multiplies; no intrinsics.
#[inline]
fn mul_128_full(a: u128, b: u128) -> (u128, u128) {
    let a_lo: u64 = a as u64;
    let a_hi: u64 = (a >> 64) as u64;
    let b_lo: u64 = b as u64;
    let b_hi: u64 = (b >> 64) as u64;

    // Schoolbook 2x2 multiplication of u64 limbs into u128 partials.
    let p00: u128 = (a_lo as u128) * (b_lo as u128); // bits [0..128)
    let p01: u128 = (a_lo as u128) * (b_hi as u128); // bits [64..192)
    let p10: u128 = (a_hi as u128) * (b_lo as u128); // bits [64..192)
    let p11: u128 = (a_hi as u128) * (b_hi as u128); // bits [128..256)

    let mask_lo: u128 = 0xFFFF_FFFF_FFFF_FFFF;

    // Middle column at bit position 64. Sum cannot overflow u128
    // because each summand is at most (2^64 - 1)^2 < 2^128 and we sum
    // three values each <= 2^128 - 2^65 + 1; the running total stays
    // below 3 * 2^128.
    let mid: u128 = (p00 >> 64) + (p01 & mask_lo) + (p10 & mask_lo);

    let low: u128 = (p00 & mask_lo) | (mid << 64);
    let high: u128 = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);

    (high, low)
}

/// splitmix64 — fast, full-period mixing of a 64-bit counter into a
/// 64-bit output. Used here purely to expand a single-`u64` seed into
/// the four-`u64` state required by xoshiro256\*\*.
#[inline]
fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(SPLITMIX_GAMMA);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_produces_a_value() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.next_u64();
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut a = Xoshiro256::seed_from_u64(1);
        let mut b = Xoshiro256::seed_from_u64(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn same_seed_produces_same_stream() {
        let mut a = Xoshiro256::seed_from_u64(42);
        let mut b = Xoshiro256::seed_from_u64(42);
        for _ in 0..256 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn zero_seed_does_not_yield_zero_state() {
        // splitmix64 of seed=0 starts at counter = GAMMA, so the state
        // is non-zero. The first output must therefore also be nonzero
        // for any reasonable initial state.
        let mut rng = Xoshiro256::seed_from_u64(0);
        assert_ne!(rng.state(), [0; 4]);
        assert_ne!(rng.next_u64(), 0);
    }

    #[test]
    fn from_state_rejects_all_zero() {
        assert!(Xoshiro256::from_state([0, 0, 0, 0]).is_none());
        assert!(Xoshiro256::from_state([0, 0, 0, 1]).is_some());
    }

    #[test]
    fn state_roundtrip_resumes_stream() {
        let mut rng = Xoshiro256::seed_from_u64(99);
        for _ in 0..17 {
            let _ = rng.next_u64();
        }
        let snap = rng.state();
        let mut resumed = Xoshiro256::from_state(snap).unwrap();
        for _ in 0..32 {
            assert_eq!(rng.next_u64(), resumed.next_u64());
        }
    }

    #[test]
    fn splitmix64_known_value_zero_counter() {
        // splitmix64(seed=0) — first output is fully determined by the
        // algorithm constants and is a canonical regression vector.
        let mut x = 0u64;
        assert_eq!(splitmix64(&mut x), 0xE220_A839_7B1D_CDAF);
    }

    #[test]
    fn xoshiro_known_first_outputs_for_seed_zero() {
        // Regression vectors: generated from the canonical
        // splitmix64 + xoshiro256** construction with seed 0. Any
        // change here is either a bug or an intentional algorithm
        // change (which would be a breaking change to determinism).
        let mut rng = Xoshiro256::seed_from_u64(0);
        let v0 = rng.next_u64();
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        let v3 = rng.next_u64();
        // First, ensure values are non-degenerate.
        assert_ne!(v0, 0);
        assert_ne!(v0, v1);
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        // Lock in determinism: replaying from the same seed produces
        // the same sequence.
        let mut rng2 = Xoshiro256::seed_from_u64(0);
        assert_eq!(rng2.next_u64(), v0);
        assert_eq!(rng2.next_u64(), v1);
        assert_eq!(rng2.next_u64(), v2);
        assert_eq!(rng2.next_u64(), v3);
    }

    #[test]
    fn next_u32_takes_high_bits() {
        // The relationship `next_u32 = (next_u64 >> 32) as u32` must
        // hold against a fresh, identically-seeded generator.
        let mut a = Xoshiro256::seed_from_u64(7);
        let mut b = Xoshiro256::seed_from_u64(7);
        for _ in 0..64 {
            let hi = (a.next_u64() >> 32) as u32;
            assert_eq!(hi, b.next_u32());
        }
    }

    #[test]
    fn next_f64_bounds() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        for _ in 0..10_000 {
            let f = rng.next_f64();
            assert!((0.0..1.0).contains(&f));
        }
    }

    #[test]
    fn fill_bytes_exact_chunks() {
        let mut a = Xoshiro256::seed_from_u64(123);
        let mut b = Xoshiro256::seed_from_u64(123);
        let mut buf = [0u8; 64];
        a.fill_bytes(&mut buf);
        for chunk in buf.chunks_exact(8) {
            let expected = b.next_u64().to_le_bytes();
            assert_eq!(chunk, expected);
        }
    }

    #[test]
    fn fill_bytes_partial_tail() {
        // Length 13 = one full 8-byte chunk plus 5 trailing bytes.
        let mut rng = Xoshiro256::seed_from_u64(2026);
        let mut buf = [0u8; 13];
        rng.fill_bytes(&mut buf);
        // Trivially: at least one byte must be nonzero — a 13-byte
        // all-zero output would be a 2^-104 freak event indicating a
        // bug, not chance.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn jump_produces_different_state() {
        let mut a = Xoshiro256::seed_from_u64(1);
        let mut b = a.clone();
        b.jump();
        assert_ne!(a.state(), b.state());
        // The two streams must not coincide on the first output.
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn long_jump_produces_different_state() {
        let mut a = Xoshiro256::seed_from_u64(1);
        let mut b = a.clone();
        b.long_jump();
        assert_ne!(a.state(), b.state());
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn jump_is_deterministic() {
        let mut a = Xoshiro256::seed_from_u64(5);
        let mut b = Xoshiro256::seed_from_u64(5);
        a.jump();
        b.jump();
        assert_eq!(a.state(), b.state());
    }

    // ------------------------------------------------------------
    // Bounded-range tests
    // ------------------------------------------------------------

    #[test]
    fn gen_range_u64_bounds() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        for _ in 0..10_000 {
            let n = rng.gen_range_u64(100..200);
            assert!((100..200).contains(&n));
        }
    }

    #[test]
    fn gen_range_u64_single_value_at_top() {
        // [start, start+1) is a one-value half-open range; every draw
        // must equal start exactly.
        let mut rng = Xoshiro256::seed_from_u64(2);
        for _ in 0..1000 {
            assert_eq!(rng.gen_range_u64(7..8), 7);
        }
    }

    #[test]
    fn gen_range_inclusive_u64_die_roll() {
        // Classic 1d6: every draw must land on a face. Over enough
        // draws we'd expect to see all six faces appear.
        let mut rng = Xoshiro256::seed_from_u64(3);
        let mut faces = [0u32; 6];
        for _ in 0..10_000 {
            let d = rng.gen_range_inclusive_u64(1..=6);
            assert!((1..=6).contains(&d));
            faces[(d - 1) as usize] += 1;
        }
        for (i, &c) in faces.iter().enumerate() {
            assert!(c > 0, "face {} never appeared in 10000 rolls", i + 1);
        }
    }

    #[test]
    fn gen_range_inclusive_u64_single_value() {
        let mut rng = Xoshiro256::seed_from_u64(4);
        for _ in 0..1000 {
            assert_eq!(rng.gen_range_inclusive_u64(42..=42), 42);
        }
    }

    #[test]
    fn gen_range_inclusive_u64_full_width_uses_raw_draw() {
        // For 0..=u64::MAX the bounded helper would compute span=2^64
        // which overflows; the implementation special-cases this and
        // returns next_u64() unchanged. Verify by checking against a
        // freshly-seeded clone.
        let mut a = Xoshiro256::seed_from_u64(5);
        let mut b = Xoshiro256::seed_from_u64(5);
        for _ in 0..256 {
            assert_eq!(a.gen_range_inclusive_u64(0..=u64::MAX), b.next_u64());
        }
    }

    #[test]
    fn gen_range_u32_bounds() {
        let mut rng = Xoshiro256::seed_from_u64(6);
        for _ in 0..10_000 {
            let n = rng.gen_range_u32(0..256);
            assert!(n < 256);
        }
    }

    #[test]
    fn gen_range_inclusive_u32_full_width() {
        // For 0..=u32::MAX every value is in-range; just verify
        // bounds + that the call doesn't panic.
        let mut rng = Xoshiro256::seed_from_u64(7);
        for _ in 0..1000 {
            let _ = rng.gen_range_inclusive_u32(0..=u32::MAX);
        }
    }

    #[test]
    fn gen_range_i64_negative_range() {
        let mut rng = Xoshiro256::seed_from_u64(8);
        for _ in 0..10_000 {
            let n = rng.gen_range_i64(-100..-50);
            assert!((-100..-50).contains(&n));
        }
    }

    #[test]
    fn gen_range_i64_mixed_sign_range() {
        let mut rng = Xoshiro256::seed_from_u64(9);
        let mut saw_neg = false;
        let mut saw_pos = false;
        for _ in 0..10_000 {
            let n = rng.gen_range_i64(-100..100);
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
    fn gen_range_inclusive_i64_full_width_is_raw_draw() {
        // i64::MIN..=i64::MAX is the full i64 space (span = 2^64).
        // The implementation reinterprets next_u64 as i64.
        let mut a = Xoshiro256::seed_from_u64(10);
        let mut b = Xoshiro256::seed_from_u64(10);
        for _ in 0..256 {
            let from_range = a.gen_range_inclusive_i64(i64::MIN..=i64::MAX);
            let from_raw = b.next_u64() as i64;
            assert_eq!(from_range, from_raw);
        }
    }

    #[test]
    fn gen_range_i32_bounds() {
        let mut rng = Xoshiro256::seed_from_u64(11);
        for _ in 0..10_000 {
            let n = rng.gen_range_i32(-1000..1000);
            assert!((-1000..1000).contains(&n));
        }
    }

    #[test]
    fn gen_range_inclusive_i32_full_width() {
        let mut rng = Xoshiro256::seed_from_u64(12);
        for _ in 0..1000 {
            let _ = rng.gen_range_inclusive_i32(i32::MIN..=i32::MAX);
        }
    }

    #[test]
    fn gen_range_f64_bounds() {
        let mut rng = Xoshiro256::seed_from_u64(13);
        for _ in 0..10_000 {
            let x = rng.gen_range_f64(-1.0..1.0);
            assert!((-1.0..1.0).contains(&x));
        }
    }

    #[test]
    fn gen_range_f64_positive_range() {
        let mut rng = Xoshiro256::seed_from_u64(14);
        for _ in 0..10_000 {
            let x = rng.gen_range_f64(10.0..20.0);
            assert!((10.0..20.0).contains(&x));
        }
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn gen_range_u64_panics_on_empty() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_u64(10..10);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    #[allow(clippy::reversed_empty_ranges)]
    fn gen_range_u64_panics_on_reverse() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_u64(10..5);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    #[allow(clippy::reversed_empty_ranges)]
    fn gen_range_inclusive_u64_panics_on_reverse() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_inclusive_u64(10..=5);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    #[allow(clippy::reversed_empty_ranges)]
    fn gen_range_i64_panics_on_reverse() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_i64(5..-5);
    }

    #[test]
    #[should_panic(expected = "non-finite")]
    fn gen_range_f64_panics_on_nan() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_f64(f64::NAN..1.0);
    }

    #[test]
    #[should_panic(expected = "non-finite")]
    fn gen_range_f64_panics_on_infinity() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_f64(0.0..f64::INFINITY);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn gen_range_f64_panics_on_reverse() {
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_f64(1.0..0.0);
    }

    #[test]
    #[should_panic(expected = "overflows to infinity")]
    fn gen_range_f64_panics_when_span_overflows() {
        // Both bounds are finite, but their difference is not. Without
        // this guard the call would return +inf or NaN for any nonzero
        // u and -inf or NaN for u == 0.
        let mut rng = Xoshiro256::seed_from_u64(1);
        let _ = rng.gen_range_f64(-f64::MAX..f64::MAX);
    }

    #[test]
    fn gen_range_f64_output_is_finite_for_finite_span() {
        let mut rng = Xoshiro256::seed_from_u64(0xF1_F1_F1);
        for _ in 0..10_000 {
            let x = rng.gen_range_f64(-1e100..1e100);
            assert!(x.is_finite(), "got non-finite {x}");
            assert!((-1e100..1e100).contains(&x));
        }
    }

    #[test]
    fn gen_range_is_deterministic_under_same_seed() {
        // Replay invariant: same seed + same sequence of calls => same
        // outputs. This is the core determinism guarantee.
        let mut a = Xoshiro256::seed_from_u64(99);
        let mut b = Xoshiro256::seed_from_u64(99);
        for _ in 0..1000 {
            assert_eq!(a.gen_range_u64(0..1000), b.gen_range_u64(0..1000));
        }
    }

    #[test]
    fn gen_range_uniformity_chi_squared() {
        // 100 000 draws over a range of 100 buckets. Expected per
        // bucket: 1000. Chi-squared critical value (99 d.f.,
        // alpha=0.001) is ~149; we use 250 to keep flake rate
        // negligible on slow CI.
        let mut rng = Xoshiro256::seed_from_u64(0xC0DE_F00D);
        let mut counts = [0u32; 100];
        for _ in 0..100_000 {
            let v = rng.gen_range_u32(0..100);
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

    #[test]
    fn gen_range_die_roll_uniformity() {
        // 600 000 die rolls. Expected count per face: 100 000.
        // Chi-squared on 5 d.f., alpha=0.001 is ~21; cap at 50.
        // Specifically targets the d6 case to catch modulo bias if
        // anyone replaces the rejection sampling with `% 6`.
        let mut rng = Xoshiro256::seed_from_u64(0xD1CE_D011);
        let mut faces = [0u32; 6];
        for _ in 0..600_000 {
            let d = rng.gen_range_inclusive_u32(1..=6);
            faces[(d - 1) as usize] += 1;
        }
        let expected = 100_000.0;
        let chi: f64 = faces
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(chi < 50.0, "d6 uniformity chi-squared {chi} too high");
    }
}
