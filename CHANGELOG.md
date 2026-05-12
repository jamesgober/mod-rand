# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/jamesgober/mod-rand/compare/v0.9.4...HEAD
[0.9.4]: https://github.com/jamesgober/mod-rand/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/jamesgober/mod-rand/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/jamesgober/mod-rand/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/jamesgober/mod-rand/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/jamesgober/mod-rand/compare/v0.1.0...v0.9.0
[0.1.0]: https://github.com/jamesgober/mod-rand/releases/tag/v0.1.0
