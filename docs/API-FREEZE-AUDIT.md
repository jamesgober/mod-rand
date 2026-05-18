# mod-rand — 1.0.0 API Freeze Audit

> Audit of every public symbol that will exist in `mod-rand 1.0.0`, the
> SemVer contract that pins them, and the symbols added since `0.9.5`.

## Status: design-stage proposal

This document is the public-surface manifest for 1.0.0. Every symbol
listed here is locked under SemVer for the 1.x line:

- **Locked.** Signatures and observable behaviour cannot change without
  a 2.x major bump.
- **Strict superset of 0.9.5.** No 0.9.5 symbol is removed, renamed, or
  has its signature altered.
- **Additions only.** Everything new is a pure addition.
- **Determinism on Tier 1 is part of the contract.** A given seed +
  given API call sequence produces identical output across the 1.x
  line. Algorithm changes that would change Tier 1 output are 2.x.

## 1. Carried forward from 0.9.5 — locked, unchanged

### 1.1 Tier 1 — `mod_rand::tier1::Xoshiro256`

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

    // Bounded integer draws — half-open
    pub fn gen_range_u64(&mut self, range: Range<u64>) -> u64;
    pub fn gen_range_u32(&mut self, range: Range<u32>) -> u32;
    pub fn gen_range_i64(&mut self, range: Range<i64>) -> i64;
    pub fn gen_range_i32(&mut self, range: Range<i32>) -> i32;

    // Bounded integer draws — inclusive
    pub fn gen_range_inclusive_u64(&mut self, range: RangeInclusive<u64>) -> u64;
    pub fn gen_range_inclusive_u32(&mut self, range: RangeInclusive<u32>) -> u32;
    pub fn gen_range_inclusive_i64(&mut self, range: RangeInclusive<i64>) -> i64;
    pub fn gen_range_inclusive_i32(&mut self, range: RangeInclusive<i32>) -> i32;

    // Bounded float draw — half-open
    pub fn gen_range_f64(&mut self, range: Range<f64>) -> f64;

    // Stream-splitting
    pub fn jump(&mut self);
    pub fn long_jump(&mut self);
}

// auto-derived
impl Debug for Xoshiro256;
impl Clone for Xoshiro256;
impl PartialEq, Eq for Xoshiro256;
```

### 1.2 Tier 2 — `mod_rand::tier2` (feature = "tier2")

```rust
// Unique values
pub fn unique_u64() -> u64;
pub fn unique_name(len: usize) -> String;
pub fn unique_base32(len: usize) -> String;
pub fn unique_hex(len: usize) -> String;

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

### 1.3 Tier 3 — `mod_rand::tier3` (feature = "tier3")

```rust
// Raw cryptographic draws
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()>;
pub fn random_u32() -> io::Result<u32>;
pub fn random_u64() -> io::Result<u64>;
pub fn random_bytes(len: usize) -> io::Result<Vec<u8>>;
pub fn random_hex(bytes: usize) -> io::Result<String>;
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

### 1.4 Special note: `random_hex` parameter semantics

`tier3::random_hex(bytes: usize) -> io::Result<String>` takes a **byte
count**, not a character count — the resulting string is exactly
`bytes * 2` lowercase hex characters. This shape is preserved verbatim
for 1.0 (renaming or changing the parameter meaning would break every
0.9.x caller). The new `tier3::random_hex_string(len)` added for 1.0
takes a character count instead, matching the rest of the new string
family.

---

## 2. New in 1.0 — pure additions

### 2.1 Full integer-width coverage

Bounded-range methods covering every integer width that callers
actually need. Lemire's "Nearly Divisionless" rejection sampling on
every type — uniform output, no modulo bias. Documented in rustdoc.

Types covered: `u8`, `u16`, `u32`, `u64`, `u128`, `usize`,
              `i8`, `i16`, `i32`, `i64`, `i128`, `isize`.

`u32`/`u64`/`i32`/`i64` already exist (carried forward). 1.0 adds the
eight remaining widths times two variants (half-open + inclusive)
across three tiers — 48 new methods/functions total:

#### Tier 1

```rust
impl Xoshiro256 {
    // half-open
    pub fn gen_range_u8(&mut self, range: Range<u8>) -> u8;
    pub fn gen_range_u16(&mut self, range: Range<u16>) -> u16;
    pub fn gen_range_u128(&mut self, range: Range<u128>) -> u128;
    pub fn gen_range_usize(&mut self, range: Range<usize>) -> usize;
    pub fn gen_range_i8(&mut self, range: Range<i8>) -> i8;
    pub fn gen_range_i16(&mut self, range: Range<i16>) -> i16;
    pub fn gen_range_i128(&mut self, range: Range<i128>) -> i128;
    pub fn gen_range_isize(&mut self, range: Range<isize>) -> isize;

    // inclusive
    pub fn gen_range_inclusive_u8(&mut self, range: RangeInclusive<u8>) -> u8;
    pub fn gen_range_inclusive_u16(&mut self, range: RangeInclusive<u16>) -> u16;
    pub fn gen_range_inclusive_u128(&mut self, range: RangeInclusive<u128>) -> u128;
    pub fn gen_range_inclusive_usize(&mut self, range: RangeInclusive<usize>) -> usize;
    pub fn gen_range_inclusive_i8(&mut self, range: RangeInclusive<i8>) -> i8;
    pub fn gen_range_inclusive_i16(&mut self, range: RangeInclusive<i16>) -> i16;
    pub fn gen_range_inclusive_i128(&mut self, range: RangeInclusive<i128>) -> i128;
    pub fn gen_range_inclusive_isize(&mut self, range: RangeInclusive<isize>) -> isize;
}
```

Tier 2 mirrors with `range_*` / `range_inclusive_*` naming.
Tier 3 mirrors with `random_range_*` / `random_range_inclusive_*`
returning `io::Result`.

**Algorithm:** 8 / 16 / 32 / `usize` (on 32-bit and 64-bit targets) and
`isize` widen to `u64` and route through `bounded_u64`. **`u128`** and
**`i128`** use a dedicated `bounded_u128` helper (Lemire's algorithm
generalised to 128-bit via a 256-bit intermediate produced by two
`u64` draws). On 64-bit targets, `usize` is `u64`-equivalent; on
32-bit targets, the `u32` path is used.

**Full-width inclusive ranges** (e.g., `0..=u8::MAX`,
`i128::MIN..=i128::MAX`) are special-cased to avoid span overflow at
the type boundary.

### 2.2 Charset constants — `mod_rand::charsets`

New top-level module exposing standard byte-slice constants for string
generation. Available in `no_std` (these are just `&'static [u8]`).

```rust
pub mod charsets {
    pub const ALPHANUMERIC: &[u8] = /* A-Z a-z 0-9, 62 bytes */;
    pub const ALPHA: &[u8]        = /* A-Z a-z, 52 bytes */;
    pub const ALPHA_LOWER: &[u8]  = /* a-z, 26 bytes */;
    pub const ALPHA_UPPER: &[u8]  = /* A-Z, 26 bytes */;
    pub const NUMERIC: &[u8]      = /* 0-9, 10 bytes */;
    pub const HEX_LOWER: &[u8]    = /* 0-9 a-f, 16 bytes */;
    pub const HEX_UPPER: &[u8]    = /* 0-9 A-F, 16 bytes */;
    pub const URL_SAFE: &[u8]     = /* RFC 4648 §5 — A-Z a-z 0-9 - _, 64 bytes */;
    pub const BASE58: &[u8]       = /* Bitcoin alphabet, no 0OIl, 58 bytes */;
    pub const BASE64: &[u8]       = /* RFC 4648 §4 — A-Z a-z 0-9 + /, 64 bytes */;
}
```

Custom charsets are accepted as `&[u8]`. Every charset must be ASCII
(every byte < 128) and non-empty; non-ASCII or empty charsets cause a
panic (Tier 1 / Tier 2) or `io::Error` with `ErrorKind::InvalidInput`
(Tier 3).

**Charset selection MUST NOT introduce modulo bias.** All charset
indexing is performed through `bounded_u64(charset.len() as u64)` —
the same Lemire rejection-sampling path used by `gen_range_*`.

### 2.3 String generation

Strings require allocation. Tier 1 string methods are gated on the
`std` feature (the type signature `-> String` already does this via
`alloc`-from-`std`; for tier1 `no_std` users, raw + bounded-range
methods remain available unchanged). Tier 2 and Tier 3 string functions
were already in a `std`-only module.

#### Tier 1 (gated on `feature = "std"`)

```rust
impl Xoshiro256 {
    pub fn gen_string(&mut self, len: usize, charset: &[u8]) -> String;
    pub fn gen_alphanumeric(&mut self, len: usize) -> String;
    pub fn gen_alpha(&mut self, len: usize) -> String;
    pub fn gen_numeric(&mut self, len: usize) -> String;
    pub fn gen_hex(&mut self, len: usize) -> String;
}
```

#### Tier 2

```rust
pub fn random_string(len: usize, charset: &[u8]) -> String;
pub fn random_alphanumeric(len: usize) -> String;
pub fn random_alpha(len: usize) -> String;
pub fn random_numeric(len: usize) -> String;
pub fn random_hex_string(len: usize) -> String;
```

Note: the existing `tier2::unique_hex(len)`, `tier2::unique_name(len)`,
and `tier2::unique_base32(len)` provide *unique-across-calls* strings.
The new `tier2::random_*` family provides random (uniformly drawn)
strings with no uniqueness guarantee — different semantics, different
use cases, both coexist.

#### Tier 3

```rust
pub fn random_string(len: usize, charset: &[u8]) -> io::Result<String>;
pub fn random_alphanumeric(len: usize) -> io::Result<String>;
pub fn random_alpha(len: usize) -> io::Result<String>;
pub fn random_numeric(len: usize) -> io::Result<String>;
pub fn random_hex_string(len: usize) -> io::Result<String>;
```

`tier3::random_hex(bytes: usize)` (the existing byte-count form) is
preserved unchanged. `random_hex_string(len)` is the new
character-count form.

### 2.4 Collection operations

Available everywhere a `&mut [T]` or `&[T]` exists. Naming convention:
methods on `Xoshiro256` use plain verb names; Tier 3 free functions
return `io::Result`.

#### Tier 1 (method on Xoshiro256)

```rust
impl Xoshiro256 {
    // Fisher-Yates shuffle (in place) — works in no_std.
    pub fn shuffle<T>(&mut self, slice: &mut [T]);

    // k references without replacement — gated on std (returns Vec).
    pub fn sample<'a, T>(&mut self, slice: &'a [T], k: usize) -> Vec<&'a T>;

    // Weighted choice — no allocation, works in no_std.
    pub fn weighted_choice<'a, T>(
        &mut self,
        items: &'a [T],
        weights: &[f64],
    ) -> Option<&'a T>;

    // Weighted index — no allocation, works in no_std.
    pub fn weighted_index(&mut self, weights: &[f64]) -> Option<usize>;
}
```

Algorithm choice (documented in rustdoc):
- **Shuffle:** in-place Fisher-Yates, O(n), no allocation, uses
  `gen_range_inclusive_usize` for index selection. Uniform over all
  permutations.
- **Sample:** **selection-sampling** (Knuth Algorithm S, *TAOCP* Vol. 2
  §3.4.2). Single pass, O(n), allocates exactly `k` slots in the
  output `Vec`. Returns references; no `T: Clone` bound. Order of
  returned references preserves slice order.
- **Weighted choice:** **cumulative-distribution method** (linear
  scan, binary-search lookup). O(weights.len()) on the search,
  zero allocation. Simpler and lower-constant than the alias method
  for the common case of one-shot weighted draws; the alias method's
  O(1) per-draw cost is only an advantage when the same weight vector
  is reused many times, which is a different access pattern and a
  candidate for a 1.x minor addition if demand surfaces.

Invalid input:
- `sample`: `k > slice.len()` panics with a clear message.
- `weighted_choice`/`weighted_index`: weight vector length mismatch
  with `items`, negative weights, or NaN weights panic. All-zero
  weights return `None`. Empty weight vector returns `None`.

#### Tier 3 (cryptographic shuffle)

```rust
pub fn shuffle<T>(slice: &mut [T]) -> io::Result<()>;
```

Tier 3 sample/weighted are intentionally not added in 1.0. Their
expected use case (cryptographic shuffle of a deck, etc.) is rare; if
demand surfaces, they fit comfortably in a 1.x minor release without
breaking anything. Tier 2 collection-ops are likewise out of 1.0 —
shuffle/sample/weighted built atop Tier 2's process-unique stream is
a niche need.

### 2.5 Distribution helpers (Tier 1)

Uniform unit-interval floats and a Bernoulli trial. No normal /
exponential / Poisson — those are explicitly deferred to 1.1+.

```rust
impl Xoshiro256 {
    pub fn gen_f64(&mut self) -> f64;   // alias for next_f64; uniform [0, 1)
    pub fn gen_f32(&mut self) -> f32;   // uniform [0, 1)
    pub fn gen_bool(&mut self, p: f64) -> bool;  // Bernoulli, p in [0, 1]
}
```

`gen_f64` is a stable alias for `next_f64`; both are kept (callers
discover one or the other based on whether they reason in terms of
"next" vs "gen" naming).
`gen_f32` uses the upper 24 mantissa bits of a `next_u32` draw,
mirroring `next_f64`'s 53-bit construction.
`gen_bool(p)` panics on `p < 0.0`, `p > 1.0`, or non-finite `p`.

## 3. Algorithm-stability commitments

Locked under the 1.x SemVer contract:

1. **Tier 1 raw stream.** `seed_from_u64(s).next_u64()` returns a
   fixed value for any given `s` — locked to splitmix64 expansion +
   xoshiro256\*\* transition. Cannot change without a 2.x bump.
   Verified by `tests/kat.rs`.
2. **Tier 1 bounded-range output.** Given the same seed + same
   sequence of `gen_range_*` calls, the output is fixed. Lemire
   rejection sampling is deterministic given a deterministic raw
   stream.
3. **Tier 1 string output.** Given the same seed + same sequence of
   `gen_string` / `gen_alphanumeric` / etc. calls, the output is
   fixed. New KAT vectors will be added under `tests/kat.rs` for
   string generation in 1.0.
4. **Tier 1 collection-op output.** Same seed + same input slice +
   same call produces the same shuffle / sample / weighted choice.
   KAT vectors added for shuffle and weighted_index.
5. **Tier 2 and Tier 3** make no reproducibility claim — those tiers
   are non-deterministic by design.

## 4. Symbols out of 1.0 — explicitly NOT added

These do not exist in 1.0 and adding them later is a minor-version
addition (not a breaking change). Listed here so they are not assumed
present:

- `Normal`, `Poisson`, `Exponential`, or any other named distribution.
- Generic `Rng` / `RngCore` / `SeedableRng` traits — concrete types
  only.
- Hardware RNG sources (RDRAND, RDSEED).
- Async API.
- Serde integration for RNG state.
- Proc-macro derive for "random struct generation."
- Tier 2 / Tier 3 sample / weighted choice. Tier 1 covers these.
- `RangeInclusive<f64>` — the probability of producing either endpoint
  is zero; the half-open `gen_range_f64` already covers the use case.
- An alias-method weighted-choice variant for high-throughput
  pre-built weight tables (candidate for 1.x minor).

## 5. REPS / DIRECTIVES alignment

The 0.9.x `REPS.md §8` and `DIRECTIVES.md §2` list
shuffle/sample/distribution helpers as "out of scope." For 1.0 those
exclusions are lifted for Tier 1 collection ops and the
`gen_f64`/`gen_f32`/`gen_bool` uniform/Bernoulli helpers. `REPS.md`
will be updated alongside this release to reflect the 1.0 scope.

The exclusions that remain in force:
- No named distributions (Normal etc.) — still out, deferred to 1.1+.
- No `Rng` / `RngCore` trait — still out.
- No hardware RNG sources — still out.
- Zero runtime dependencies beyond `std` — still in force, no
  exceptions.
- MSRV 1.75 — still in force, no exceptions.

## 6. Total surface summary

| Category                 | 0.9.5 count | 1.0.0 count | Δ      |
|--------------------------|-------------|-------------|--------|
| Tier 1 methods           | 19          | 19 + 16 (widths) + 5 (strings) + 4 (coll-ops) + 3 (dist) = **47** | +28 |
| Tier 2 free functions    | 12          | 12 + 16 (widths) + 5 (strings) = **33** | +21 |
| Tier 3 free functions    | 14          | 14 + 16 (widths) + 5 (strings) + 1 (shuffle) = **36** | +22 |
| Top-level modules        | 3 (tier1/tier2/tier3) | **4** (+ `charsets`) | +1 |
| Charset constants        | 0           | **10**       | +10 |
| **Total public symbols** | 48          | **126**      | +78 |

Every counted addition is a pure addition. No removals, no renames,
no signature changes.
