# mod-rand — Project Specification (REPS)

> Rust Engineering Project Specification.
> Normative language follows RFC 2119.

## 1. Purpose

`mod-rand` MUST provide random number generation at three quality
tiers in a single zero-dependency library. Users pick the tier
appropriate to their threat model.

## 2. The three tiers

### Tier 1: Fast deterministic PRNG

MUST be:
- Seedable from a single `u64`
- Reproducible (same seed produces same stream)
- Fast (target: ~1 ns per `u64` on commodity hardware)
- Available in `no_std`
- Algorithm: xoshiro256\*\* with splitmix64 seeding

MUST NOT be:
- Used for security-sensitive randomness
- Marketed as cryptographically secure

### Tier 2: Process-unique seeds

MUST be:
- Different across calls within a process (counter-guaranteed)
- Different across processes with extremely high probability
- Fast (target: <100 ns per call)
- Available when `std` feature is enabled
- Algorithm: PID + nanosecond timestamp + atomic counter + per-process
  salt, mixed with a strong 64-bit avalanche function (Stafford
  variant 13)

MUST NOT be:
- Used for security-sensitive randomness
- Used where two simultaneous calls returning the same value would
  cause correctness bugs (the counter prevents this, but only within
  a single process)

### Tier 3: OS-backed cryptographic random

MUST be:
- Backed by the OS's secure random source:
  - Linux: `getrandom(2)` syscall
  - macOS: `getentropy(3)`
  - Windows: `BCryptGenRandom`
  - Other Unix: `/dev/urandom`
- Cryptographically secure (output unpredictable by an attacker)
- Available when `std` feature is enabled
- Resilient to fork / snapshot / VM-resume (no internal state to mix)

MUST NOT be:
- Optimized for speed at the cost of security
- Allowed to silently fall back to a weaker source on syscall failure
  (MUST return an error instead)

## 3. API surface

### 3.1 Tier 1

```rust
pub struct Xoshiro256 { /* private */ }

impl Xoshiro256 {
    // Construction
    pub fn seed_from_u64(seed: u64) -> Self;
    pub fn from_state(state: [u64; 4]) -> Option<Self>;
    pub fn state(&self) -> [u64; 4];

    // Raw draws
    pub fn next_u64(&mut self) -> u64;
    pub fn next_u32(&mut self) -> u32;
    pub fn next_f64(&mut self) -> f64;
    pub fn fill_bytes(&mut self, buf: &mut [u8]);

    // Bounded integer draws — half-open [start, end)
    pub fn gen_range_u64(&mut self, range: Range<u64>) -> u64;
    pub fn gen_range_u32(&mut self, range: Range<u32>) -> u32;
    pub fn gen_range_i64(&mut self, range: Range<i64>) -> i64;
    pub fn gen_range_i32(&mut self, range: Range<i32>) -> i32;

    // Bounded integer draws — inclusive [start, end]
    pub fn gen_range_inclusive_u64(&mut self, range: RangeInclusive<u64>) -> u64;
    pub fn gen_range_inclusive_u32(&mut self, range: RangeInclusive<u32>) -> u32;
    pub fn gen_range_inclusive_i64(&mut self, range: RangeInclusive<i64>) -> i64;
    pub fn gen_range_inclusive_i32(&mut self, range: RangeInclusive<i32>) -> i32;

    // Bounded float draw — half-open [start, end)
    pub fn gen_range_f64(&mut self, range: Range<f64>) -> f64;

    // Stream-splitting
    pub fn jump(&mut self);
    pub fn long_jump(&mut self);
}
```

### 3.2 Tier 2

```rust
// Unique values
pub fn unique_u64() -> u64;
pub fn unique_name(len: usize)   -> String;
pub fn unique_base32(len: usize) -> String;
pub fn unique_hex(len: usize)    -> String;

// Bounded integer draws — half-open
pub fn range_u64(range: Range<u64>) -> u64;
pub fn range_u32(range: Range<u32>) -> u32;
pub fn range_i64(range: Range<i64>) -> i64;
pub fn range_i32(range: Range<i32>) -> i32;

// Bounded integer draws — inclusive
pub fn range_inclusive_u64(range: RangeInclusive<u64>) -> u64;
pub fn range_inclusive_u32(range: RangeInclusive<u32>) -> u32;
pub fn range_inclusive_i64(range: RangeInclusive<i64>) -> i64;
pub fn range_inclusive_i32(range: RangeInclusive<i32>) -> i32;
```

### 3.3 Tier 3

```rust
// Raw cryptographic draws
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()>;
pub fn random_u32()               -> io::Result<u32>;
pub fn random_u64()               -> io::Result<u64>;
pub fn random_bytes(len: usize)   -> io::Result<Vec<u8>>;
pub fn random_hex(bytes: usize)   -> io::Result<String>;
pub fn random_base32(chars: usize) -> io::Result<String>;

// Bounded integer draws — half-open
pub fn random_range_u64(range: Range<u64>) -> io::Result<u64>;
pub fn random_range_u32(range: Range<u32>) -> io::Result<u32>;
pub fn random_range_i64(range: Range<i64>) -> io::Result<i64>;
pub fn random_range_i32(range: Range<i32>) -> io::Result<i32>;

// Bounded integer draws — inclusive
pub fn random_range_inclusive_u64(range: RangeInclusive<u64>) -> io::Result<u64>;
pub fn random_range_inclusive_u32(range: RangeInclusive<u32>) -> io::Result<u32>;
pub fn random_range_inclusive_i64(range: RangeInclusive<i64>) -> io::Result<i64>;
pub fn random_range_inclusive_i32(range: RangeInclusive<i32>) -> io::Result<i32>;
```

## 4. Bounded-range semantics

The bounded-range API MUST satisfy these properties on every tier:

### 4.1 Range syntax

- `start..end` (`Range<T>`) MUST be treated as half-open: the produced
  value satisfies `start <= v < end`.
- `start..=end` (`RangeInclusive<T>`) MUST be treated as inclusive:
  the produced value satisfies `start <= v <= end`.

The caller's choice of `..` vs `..=` IS the contract. No tier accepts
a two-argument `(min, max)` form; the ambiguity that would create is
the reason we use range syntax.

### 4.2 Uniformity (no modulo bias)

For any non-empty integer range, every value in the range MUST be
producible, and over a large number of draws the empirical
distribution MUST converge to uniform. Implementations MUST NOT use
naive `value % n` reduction; they MUST use unbiased rejection
sampling.

The reference algorithm is Daniel Lemire's "Nearly Divisionless"
random integer generation (J. ACM 2019). Equivalent algorithms with
the same uniformity guarantee are acceptable.

The crate's integration tests MUST include at least one chi-squared
uniformity test over a large sample (≥1,000,000 draws) for at least
one tier; this test MUST pass before any release.

### 4.3 Invalid ranges

- An empty range (`start >= end` for half-open; `start > end` for
  inclusive) is a programming error.
  - Tier 1 and Tier 2 MUST panic with a descriptive message.
  - Tier 3 MUST return `io::Error` with `ErrorKind::InvalidInput` and
    a descriptive message.
- A single-value inclusive range (`start..=start`) MUST return
  `start` without a redundant draw.
- The full-width inclusive range (`T::MIN..=T::MAX`) MUST be supported
  and equivalent to a raw `next_uN` / `random_uN` draw.

### 4.4 Float ranges

- Only `Range<f64>` (half-open) is supported. There is no
  `RangeInclusive<f64>` API; the probability of producing either
  endpoint exactly is zero in any case.
- If either bound is non-finite (NaN or infinity), Tier 1 MUST panic.
- If `start >= end`, Tier 1 MUST panic.
- The implementation uses `next_f64()` (a uniform draw in `[0, 1)`)
  and maps it linearly into the requested range.

### 4.5 Signed integers

- For `Range<i32>` / `Range<i64>` and the corresponding
  `RangeInclusive`, the span between bounds is computed in a wider
  unsigned type (u128 internally) to avoid signed overflow at extreme
  endpoints.
- `RangeInclusive<i64>` covering the entire `i64::MIN..=i64::MAX`
  range MUST be supported and equivalent to reinterpreting a raw
  `next_u64` / `random_u64` draw as `i64`.

## 5. Determinism

- Tier 1 output MUST be deterministic given a seed. This includes
  bounded-range output: replaying a seed produces the same sequence
  of bounded values from the same sequence of `gen_range_*` calls.
- Tier 2 output MUST be unique across calls within a process.
  Bounded-range Tier 2 output makes no uniqueness guarantee (the
  reduction maps multiple `u64` inputs to the same bounded value by
  construction).
- Tier 3 output MUST be non-deterministic.

## 6. Dependencies

This crate MUST NOT have runtime dependencies outside of `std` (when
the `std` feature is enabled). Platform-specific FFI declarations
SHOULD be inlined rather than pulled in via `libc`.

The point: this crate exists partly to break the `getrandom`-induced
MSRV ratchet. We cannot replace one MSRV-locking dep with another.

## 7. Stability

Through `0.9.x` the public API MAY shift in minor ways. The `1.0`
release pins the API and the tier definitions.

## 8. Out of scope

- Generic distribution types (Normal, Poisson, Exponential, etc.) —
  that is `rand_distr` territory.
- Trait-heavy abstraction (`Rng` / `RngCore` / `SeedableRng`) — we
  expose concrete types.
- Hardware random sources (RDRAND, RDSEED) — may revisit if there is
  demand.
- Multi-thread coordination (shared atomic-state RNGs) — Tier 2's
  atomic counter is enough; if users want a shared Tier 1, they wrap
  one themselves.
- Sampling from arbitrary collections (`choose`, `shuffle`) — easy
  to build on top of `gen_range_*` and out of scope for this crate.
