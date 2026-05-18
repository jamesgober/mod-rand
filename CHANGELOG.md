# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-05-18

The `1.0` release pins the public API for the entire `1.x` line.
See [`docs/STABILITY.md`](docs/STABILITY.md) for the binding SemVer
policy and [`docs/API-FREEZE-AUDIT.md`](docs/API-FREEZE-AUDIT.md) for
the full surface manifest.

`1.0.0` is a strict superset of `0.9.5`: every public symbol that
existed in `0.9.5` continues to work with no source changes. The
release expands the scope from "tiered random number generation" to
"tiered randomness" — numbers, bytes, strings, tokens, and collection
operations covered in a single zero-dependency library.

### Added — full integer-width coverage on every tier

Bounded uniform integer draws on every primitive integer width that
callers actually need. Each width gets both half-open (`..`) and
inclusive (`..=`) variants across all three tiers — Lemire's "Nearly
Divisionless" rejection sampling throughout, so output is uniformly
distributed with no modulo bias.

Widths added (`u32`/`u64`/`i32`/`i64` already shipped in `0.9.4`):

- **Unsigned:** `u8`, `u16`, `u128`, `usize`.
- **Signed:** `i8`, `i16`, `i128`, `isize`.

48 new methods/functions total — 16 per tier:

- **Tier 1**: `Xoshiro256::gen_range_u8` / `gen_range_u16` /
  `gen_range_u128` / `gen_range_usize` / `gen_range_i8` /
  `gen_range_i16` / `gen_range_i128` / `gen_range_isize`, each with
  matching `gen_range_inclusive_*` variant.
- **Tier 2**: `range_u8` / `range_u16` / `range_u128` / `range_usize`
  / `range_i8` / `range_i16` / `range_i128` / `range_isize`, each
  with matching `range_inclusive_*` variant.
- **Tier 3**: `random_range_u8` / `random_range_u16` /
  `random_range_u128` / `random_range_usize` / `random_range_i8` /
  `random_range_i16` / `random_range_i128` / `random_range_isize`,
  each with matching `random_range_inclusive_*` variant — all
  returning `io::Result<T>`.

128-bit ranges use a dedicated 256-bit-intermediate generalisation of
Lemire's algorithm; two `u64` draws (or two syscalls on Tier 3) per
draw in the common case. Full-width inclusive ranges (`0..=u128::MAX`,
`i128::MIN..=i128::MAX`) are special-cased to a raw 128-bit
reinterpret to avoid span overflow at the type boundary.

### Added — `charsets` module

New top-level module exposing standard byte-slice constants for
string generation. Available in `no_std` (these are `&'static [u8]`):

`charsets::ALPHANUMERIC`, `ALPHA`, `ALPHA_LOWER`, `ALPHA_UPPER`,
`NUMERIC`, `HEX_LOWER`, `HEX_UPPER`, `URL_SAFE` (RFC 4648 §5),
`BASE58` (Bitcoin alphabet), `BASE64` (RFC 4648 §4).

### Added — string generation across every tier

Selection uses Lemire rejection sampling against `charset.len()` —
the per-character distribution is uniform, with no modulo bias from
the charset reduction.

**Tier 1** (gated on `feature = "std"` because `String` requires
allocation):

- `Xoshiro256::gen_string(len, charset)` — custom charset.
- `Xoshiro256::gen_alphanumeric(len)`, `gen_alpha(len)`,
  `gen_numeric(len)`, `gen_hex(len)`.

**Tier 2**: `random_string` / `random_alphanumeric` / `random_alpha`
/ `random_numeric` / `random_hex_string`. These complement (do not
replace) the existing `unique_*` family — `unique_*` makes a
per-call distinctness claim; `random_*` makes a uniform-distribution
claim. Both shipped alongside one another.

**Tier 3**: `random_string` / `random_alphanumeric` / `random_alpha`
/ `random_numeric` / `random_hex_string` — all returning
`io::Result<String>`. The existing `random_hex(bytes)` (byte-count
form) is preserved unchanged; `random_hex_string(len)` is the new
character-count form.

Charset validation:
- Tier 1, Tier 2: panic on empty or non-ASCII charset.
- Tier 3: returns `io::Error::new(ErrorKind::InvalidInput, ...)`.

### Added — collection operations

**Tier 1** (`Xoshiro256` methods):

- `shuffle<T>(&mut self, slice: &mut [T])` — in-place Fisher-Yates,
  O(n), no allocation. Available in `no_std`.
- `sample<'a, T>(&mut self, slice: &'a [T], k: usize) -> Vec<&'a T>` —
  selection sampling (Knuth Algorithm S). Returns references, no
  `T: Clone` bound. Preserves source-slice order. Gated on `std`.
- `weighted_index(&mut self, weights: &[f64]) -> Option<usize>` —
  cumulative-distribution method. O(weights.len()) per call, no
  allocation. Returns `None` for empty / all-zero weights. Panics
  on negative / NaN / non-finite weights.
- `weighted_choice<'a, T>(&mut self, items: &'a [T], weights: &[f64]) -> Option<&'a T>` —
  thin wrapper around `weighted_index` returning the referenced item.

**Tier 3**: `shuffle<T>(slice: &mut [T]) -> io::Result<()>` —
cryptographic Fisher-Yates. Each swap consumes one `random_u64`
worth of OS entropy.

### Added — Tier 1 distribution helpers

- `Xoshiro256::gen_f64()` — uniform `[0.0, 1.0)`. Stable alias for
  `next_f64`; both methods produce identical output.
- `Xoshiro256::gen_f32()` — uniform `[0.0, 1.0)`. Uses the upper 24
  mantissa bits of a `next_u32` draw.
- `Xoshiro256::gen_bool(p: f64)` — Bernoulli trial. Panics on
  non-finite `p` or `p` outside `[0.0, 1.0]`.

Named distributions (Normal, Poisson, Exponential, etc.) remain out
of scope for `1.0`; they are candidates for a `1.x` minor release if
demand surfaces.

### Added — algorithm-stability KAT vectors

`tests/kat.rs` extended with new known-answer vectors that pin the
Tier 1 determinism contract for the new APIs:

- `kat_gen_alphanumeric_seed_one`
- `kat_gen_hex_seed_42_is_determined`
- `kat_shuffle_seed_one_is_determined`
- `kat_weighted_index_seed_one_is_determined`
- `kat_gen_range_u128_seed_one_is_determined`
- `kat_gen_range_inclusive_i128_full_width_is_determined`

Any future edit that changes Tier 1 output for these inputs trips a
test failure immediately — by definition a determinism break under
the `1.x` SemVer contract.

### Added — integration test coverage

- `tests/widths.rs` — cross-tier bounded-range coverage for the
  eight new integer widths, plus a 100_000-draw chi-squared on Tier
  1's `gen_range_u128`.
- `tests/strings.rs` — length / alphabet / charset-validation /
  determinism tests across every tier, plus a 100_000-character
  chi-squared on Tier 1's `gen_alphanumeric` alphabet usage.
- `tests/collections.rs` — multiset preservation for shuffle, 60_000
  shuffle-permutation chi-squared, no-duplicates property for
  sample, 50_000-draw chi-squared on `weighted_index` against the
  declared weight distribution.
- `tests/distribution.rs` — `gen_f32` decile chi-squared and
  `gen_bool` chi-squared at p=0.5 and p=0.25.

### Added — benchmarks

`benches/tier1.rs`, `benches/tier2.rs`, and `benches/tier3.rs`
extended with new benchmark targets covering every new operation:
additional integer widths, distribution helpers, string generation
(at 16 and 64 characters), and collection ops (shuffle at sizes 10,
100, 1000, 10000; sample of k=10 from n=1000; weighted_index over
10, 100, 1000 weights).

### Added — documentation

- `docs/API-FREEZE-AUDIT.md` — the binding manifest of every public
  symbol that exists in `1.0.0`, what carried forward from `0.9.5`,
  and what is added.
- `docs/STABILITY.md` — the formal SemVer / determinism / MSRV /
  deprecation policy for the `1.x` line.
- `docs/COMPARISON.md` — honest side-by-side with `rand`,
  `fastrand`, and `nanorand`, including non-strengths of mod-rand.

### Changed

- README rewritten to reflect the broader scope. The library is
  positioned as a tiered *randomness* library (numbers + bytes +
  strings + tokens + collection ops), not strictly a "random number
  generation" library. Performance numbers updated to include the
  new operations. Comparison-table section added at the end of the
  README.
- `Cargo.toml` `description` updated to reflect the broader scope.
- `Cargo.toml` `keywords` polished for crates.io discoverability.

### Performance

Representative numbers on Ryzen 9 9950X3D / Windows 11 from
`cargo bench`. The full table is in the README.

**Tier 1** (xoshiro256\*\*):

| op                                    | time      |
|---------------------------------------|-----------|
| `next_u64`                            | ~0.6 ns   |
| `gen_range_u8(0..100)`                | ~0.8 ns   |
| `gen_range_u128(0..u128::MAX/2)`      | ~2.2 ns   |
| `gen_range_inclusive_u128(0..=u128::MAX)` | ~1.1 ns |
| `gen_f32`                             | ~0.7 ns   |
| `gen_bool(0.5)`                       | ~0.8 ns   |
| `gen_alphanumeric(16)`                | ~58 ns    |
| `gen_hex(32)`                         | ~63 ns    |
| `shuffle(100)`                        | ~104 ns   |
| `shuffle(1000)`                       | ~953 ns   |
| `sample(k=10, n=1000)`                | ~905 ns   |
| `weighted_index(100 weights)`         | ~172 ns   |

**Tier 2** (process-unique, dominated by `SystemTime::now()`):

| op                                    | time      |
|---------------------------------------|-----------|
| `unique_u64`                          | ~21 ns    |
| `range_u128(0..u128::MAX/2)`          | ~45 ns    |
| `random_alphanumeric(16)`             | ~420 ns   |

**Tier 3** (OS CSPRNG, syscall-bound):

| op                                    | time (Win)|
|---------------------------------------|-----------|
| `random_u64`                          | ~35 ns    |
| `random_range_u128(0..u128::MAX/2)`   | ~48 ns    |
| `random_alphanumeric(16)`             | ~628 ns   |
| `shuffle(52)` (deck of cards)         | ~1.9 µs   |
| `shuffle(1000)`                       | ~38 µs    |

Linux/macOS Tier 3 numbers are kernel-dependent; expect 100–500 ns
per call on commodity hardware.

### Compatibility

- Strict superset of `0.9.5`: every `0.9.5` public symbol works
  unchanged.
- MSRV stays at `1.75`. No bump.
- Zero runtime dependencies. The `[dependencies]` table remains empty.
- No new feature flags. Default features unchanged
  (`["std", "tier2", "tier3"]`).

## [0.9.5] - 2026-05-12

### Fixed

- `tier1::Xoshiro256::gen_range_f64` now panics when the requested
  span `end - start` overflows to infinity (e.g.,
  `-f64::MAX..f64::MAX`). Previously the function checked that each
  bound was finite but not the span, so symmetric extreme ranges could
  return `+inf` or `NaN`. The returned value is now guaranteed finite
  for every finite, in-range pair of bounds. Two new unit tests cover
  the guard and the "finite span ⇒ finite output" invariant.

### Documentation

- README now showcases the bounded-range API alongside the headline
  raw-draw example, and the performance table includes representative
  bounded-range entries.
- Rustdoc on `gen_range_f64` documents the new span-overflow panic and
  guarantees finite output for finite, non-overflowing spans.

## [0.9.4] - 2026-05-12

### Added — bounded-range API

- Bounded uniform integer draws on every tier using the Rust range
  syntax (`..` for half-open, `..=` for inclusive). The caller's
  choice of `..` vs `..=` IS the contract — no two-argument
  `(min, max)` form, no ambiguity. 25 new public APIs:
  - **Tier 1**: `Xoshiro256::gen_range_u64`, `gen_range_u32`,
    `gen_range_i64`, `gen_range_i32`, `gen_range_f64`, plus the four
    `gen_range_inclusive_*` integer variants.
  - **Tier 2**: `range_u64`, `range_u32`, `range_i64`, `range_i32`,
    and the four `range_inclusive_*` variants.
  - **Tier 3**: `random_range_u64`, `random_range_u32`,
    `random_range_i64`, `random_range_i32`, and the four
    `random_range_inclusive_*` variants — all returning
    `io::Result<T>`.
- All bounded methods use **Daniel Lemire's "Nearly Divisionless"
  rejection sampling** (J. ACM 2019). Output is uniformly
  distributed; there is no modulo bias. Average rejection rate is
  effectively zero for any range smaller than half the `u64` space.
- Full-width inclusive ranges (`0..=u64::MAX`, `i64::MIN..=i64::MAX`,
  etc.) are special-cased to avoid `span = 2^64` overflow and are
  equivalent to reinterpreting a raw `next_uN` / `random_uN` draw.
- Mixed-sign and negative integer ranges are supported on all signed
  integer methods via internal `i128` span computation.
- `gen_range_f64` (Tier 1 only) draws a uniform float in
  `[start, end)` by mapping `next_f64() * (end - start) + start`.
  There is no inclusive float variant — the probability of producing
  either endpoint exactly is zero for any reasonable range.
- Invalid-range handling:
  - **Tier 1 & 2**: Panic with a descriptive message on empty or
    reversed ranges; Tier 1 `f64` additionally panics on non-finite
    bounds (NaN / ±∞).
  - **Tier 3**: Returns `io::Error::new(ErrorKind::InvalidInput, …)`
    on empty or reversed ranges, matching its existing fallible
    API surface. No panic.

### Added — tests, examples, benches

- `tests/range.rs` — cross-tier integration tests covering:
  - 1,000,000-draw chi-squared uniformity tests on Tier 1 and Tier 2.
  - 50,000-draw chi-squared on Tier 3.
  - 600,000-roll six-sided die test (the canonical modulo-bias trap;
    `2^64 % 6 = 4`, so a naive `% 6` reduction would visibly skew the
    distribution and fail this test).
  - Single-value, full-width, and mixed-sign range edge cases on all
    three tiers.
  - Tier 1 determinism: replaying a seed produces identical bounded
    output for the same `gen_range_*` call sequence.
- 58 new in-crate unit tests across `src/tier1.rs`, `src/tier2.rs`,
  and `src/tier3.rs` covering per-method bounds, single-value
  ranges, full-width ranges, panic / error paths, and per-tier
  chi-squared distribution checks.
- `examples/bounded_ranges.rs` — runnable demonstration of every
  tier's bounded-range API, including a 3d6 dice roll, signed and
  float ranges, and Tier 3 error handling on empty range.
- Bounded-range benchmarks added to `benches/tier1.rs`,
  `benches/tier2.rs`, and `benches/tier3.rs`, including a
  worst-case rejection-rate scenario for Tier 1
  (`gen_range_u64(0..⅔·u64::MAX)`).

### Added — earlier in 0.9.4

- `tests/kat.rs` — hardcoded known-answer test vectors for Tier 1.
  Covers `seed_from_u64` with seeds `{0, 1, 42, u64::MAX}`, the first
  8 outputs each, plus post-`jump`/post-`long_jump` vectors for
  seed=1. Locks in the algorithm against any future edit that
  inadvertently changes the constants.
- `tests/concurrency.rs` — Tier 2 uniqueness under 8-thread
  contention (400,000 raw `unique_u64` and 160,000 `unique_name(20)`,
  all distinct), and Tier 3 stress under multi-thread load.
- Thread-safety notes in Tier 2 and Tier 3 module docs making the
  guarantee explicit.
- `.dev/AUDIT.md` — self-audit report against `DIRECTIVES.md` and
  `REPS.md` (local-only).

### Performance

Measured on Nexus (Ryzen 9 9950X3D, Windows 11) via `cargo bench`:

| op                                          | time     |
|---------------------------------------------|----------|
| `gen_range_u64(0..100)` (Tier 1)            | ~0.9 ns  |
| `gen_range_inclusive_u32(1..=6)` (Tier 1)   | ~0.9 ns  |
| `gen_range_u64(0..⅔·u64::MAX)` worst case   | ~6 ns    |
| `range_u64(0..100)` (Tier 2)                | ~21 ns   |
| `random_range_u64(0..100)` (Tier 3)         | ~35 ns   |

The rejection-sampling layer adds essentially no overhead beyond the
raw `next_u64` / `unique_u64` / `random_u64` baseline in the
common case.

## [0.9.3] - 2026-05-11

### Added

- `docs/API.md` — hand-written API reference covering every tier's
  guarantees, performance targets, and non-guarantees.
- Per-tier runnable examples: `tier1_simulation` (Monte Carlo π
  estimate), `tier2_tempdir` (process-unique names), `tier3_token`
  (cryptographic tokens, keys, salts).
- Zero-dependency benchmark harness in `benches/` covering all three
  tiers. Runs with plain `cargo bench --bench tier{1,2,3}`.
- README updated with measured per-tier performance numbers.

## [0.9.2] - 2026-05-11

### Added — Tier 3 real implementation

- Direct platform syscalls replace the placeholder:
  - **Linux**: `getrandom(2)` via inline `extern "C"` (no `libc`
    crate, no `getrandom` crate). `EINTR` is retried transparently.
    On `ENOSYS` (kernel older than 3.17 — older than any supported
    Rust target), falls back to `/dev/urandom`. `/dev/urandom` is a
    cryptographic source on every supported platform; this is not a
    security downgrade. Fallback is taken on *unavailable* syscall,
    never on a *failed* one.
  - **macOS**: `getentropy(3)` from libSystem. Requests larger than
    256 bytes are chunked. `EINTR` is retried.
  - **Windows**: `BCryptGenRandom` from `bcrypt.dll` with
    `BCRYPT_USE_SYSTEM_PREFERRED_RNG` (null algorithm handle).
    NTSTATUS failures surface in the returned `io::Error`.
  - **Other Unix**: `/dev/urandom` read.
  - **Other platforms**: `io::ErrorKind::Unsupported`.
- `tier3::random_bytes(len)` — convenience for callers without a
  pre-allocated buffer.
- `tier3::random_u32()` — 32-bit cryptographic draw.
- `tier3::random_base32(chars)` — Crockford base32 token of an exact
  character count.

### Changed

- `tier3::fill_bytes` short-circuits on empty buffers (no syscall).
- `tier3::random_hex` uses a fixed-size lookup table rather than
  per-byte `format!`, avoiding heap traffic.

### Security

- On every platform, syscall / API failure returns `io::Error`. There
  is **no** silent fallback to a non-cryptographic source.

## [0.9.1] - 2026-05-11

### Added — Tier 2 real implementation

- Stafford-variant-13 avalanche mixer over (PID, nanos, atomic
  counter, per-process salt) replaces the placeholder multiply-XOR.
- Lazy per-process salt: captured on first use so two processes
  started in the same nanosecond with the same PID (e.g., container
  restart) still diverge from their first call.
- `tier2::unique_hex(len)` — exact-length lowercase hex.
- `tier2::unique_base32(len)` — exact-length Crockford base32
  (synonym of `unique_name`).

### Changed

- `tier2::unique_name(len)` now returns *exactly* `len` characters
  (previously returned `>= len`). Callers depending on the old
  rounding behaviour need to adjust.
- Counter is mixed in via XOR rather than addition so it can never be
  cancelled by other contributions; guarantees no collisions across
  same-process calls for the full 2^64 range.

## [0.9.0] - 2026-05-11

### Added — Tier 1 real implementation

- Full xoshiro256\*\* algorithm per the canonical reference at
  <https://prng.di.unimi.it/xoshiro256starstar.c>.
- splitmix64-based seed expansion: a single `u64` is expanded to the
  four-`u64` xoshiro state via four splitmix64 rounds, the seeding
  strategy recommended by the xoshiro authors.
- `Xoshiro256::jump()` — advances by 2^128 calls; provides
  non-overlapping parallel substreams.
- `Xoshiro256::long_jump()` — advances by 2^192 calls.
- `Xoshiro256::from_state(state)` — construct from a raw 256-bit
  state. Rejects the all-zero state (the single fixed point of the
  xoshiro transition).
- `Xoshiro256::state()` — checkpoint a stream for later resume.
- `Xoshiro256::next_u32()` — takes the high 32 bits of a `next_u64`
  draw (the stronger half per the xoshiro authors).
- `Xoshiro256::next_f64()` — uniform double in `[0.0, 1.0)` using the
  upper 53 mantissa bits.
- `Xoshiro256::fill_bytes(buf)` — chunked, little-endian fill.
- Integration tests (`tests/statistical.rs`) covering chi-squared,
  runs test, low/high byte uniformity, decile uniformity for
  `next_f64`, and jump independence.

### Changed

- `seed_from_u64(0)` no longer special-cases the seed (placeholder
  upgraded the seed to `1`). The splitmix64 counter starts at
  `0 + GAMMA`, which is non-zero; the resulting xoshiro state is
  therefore guaranteed non-degenerate.

## [0.1.0] - 2026-05-11

### Added

- Initial crate skeleton.
- `tier1` module: `Xoshiro256` struct with `seed_from_u64` and
  `next_u64` (placeholder implementation).
- `tier2` module: `unique_u64` and `unique_name` functions
  (placeholder mixing function).
- `tier3` module: `fill_bytes`, `random_u64`, `random_hex` functions
  (placeholder; NOT cryptographically secure in this release).
- Feature flags: `std` (default), `tier2` (default), `tier3` (default).
- Smoke tests for each tier.

### Note

This was the name-claim release. The real implementations land in
`0.9.x` (this release).

**Do not use tier3 from `v0.1.0` for security-sensitive work.** The
placeholder is not cryptographically secure. Upgrade to `0.9.2+`.

[Unreleased]: https://github.com/jamesgober/mod-rand/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jamesgober/mod-rand/compare/v0.9.5...v1.0.0
[0.9.5]: https://github.com/jamesgober/mod-rand/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/jamesgober/mod-rand/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/jamesgober/mod-rand/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/jamesgober/mod-rand/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/jamesgober/mod-rand/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/jamesgober/mod-rand/compare/v0.1.0...v0.9.0
[0.1.0]: https://github.com/jamesgober/mod-rand/releases/tag/v0.1.0
