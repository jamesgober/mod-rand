# mod-rand — Stability and SemVer Policy

> This document is the formal stability contract for the `1.x` line.
> It is binding: any release that violates it is a bug.

## Headline guarantee

**Every public symbol in `1.0.0` is locked for the entire `1.x` line.**
Signatures, observable behaviour, and (for Tier 1) byte-for-byte output
for a given seed and call sequence cannot change without a major
version bump to `2.0.0`.

This applies to:

- Every symbol re-exported under `mod_rand::tier1`, `mod_rand::tier2`,
  `mod_rand::tier3`, and `mod_rand::charsets`.
- The trait implementations on `Xoshiro256` (`Debug`, `Clone`, `Eq`,
  `PartialEq`).
- The numeric values of every `charsets::*` constant.

## Version policy

The `1.x` line follows [Semantic Versioning 2.0.0](https://semver.org/).
The specific rules for this crate:

### Patch releases (`1.x.Y`)

May contain:

- Bug fixes that do not change observable output for a given seed (Tier
  1) or change the documented contract (Tier 2 / Tier 3).
- Documentation improvements.
- Internal performance work that does not move any public surface.
- Test additions.

May NOT contain:

- New public items.
- Changes to Tier 1 output for any given `(seed, call sequence)` pair.
- MSRV bumps.

### Minor releases (`1.Y.0`)

May contain everything a patch release may contain, plus:

- New public items (functions, methods, constants, modules) so long as
  they are pure additions — no signature change to any existing symbol.
- New optional Cargo features that default to off, or that activate
  purely additive code paths.
- MSRV bumps. Each MSRV bump is a minor-version bump minimum and is
  called out in the CHANGELOG.

### Major releases (`2.0.0`)

Required for any change that violates the above. Specifically, any
of the following requires `2.0.0`:

- Removal or rename of any public symbol.
- A signature change to any existing public symbol (including making
  panicking conditions stricter or looser in a user-observable way).
- A change to Tier 1's output for any `(seed, call sequence)` pair —
  i.e., breaking algorithmic determinism on Tier 1.
- Changing the byte values of any `charsets::*` constant (these are
  effectively format-level — re-ordering or substituting any byte is
  a breaking change).
- A change to the documented invariants of Tier 2 or Tier 3 (e.g., if
  Tier 3 ever fell back to a non-cryptographic source, that's `2.0.0`).
  Note: before `1.1.0` the docs claimed every Tier 2 `unique_u64` call
  in a process returns a distinct value. The code never guaranteed that
  across clock ticks (collisions follow the 64-bit birthday bound), so
  `1.1.0` corrected the docs; the behaviour did not change.

## Determinism on Tier 1

Tier 1 (`mod_rand::tier1::Xoshiro256`) is **deterministic** under the
following identity:

```text
Xoshiro256::seed_from_u64(s)
    .call(api_1)
    .call(api_2)
    ...
    .call(api_N)
```

For any fixed `s` and fixed sequence of API calls, the result is
identical across every `1.x` release on every platform.

This includes, specifically:

- `next_u64`, `next_u32`, `next_f64`, `fill_bytes`.
- Every `gen_range_*` and `gen_range_inclusive_*` method, on every
  integer width and on `f64`.
- `gen_f64`, `gen_f32`, `gen_bool`.
- `gen_string`, `gen_alphanumeric`, `gen_alpha`, `gen_numeric`,
  `gen_hex`.
- `shuffle`, `sample`, `weighted_index`, `weighted_choice`.
- `jump`, `long_jump`.

Determinism is enforced by hardcoded known-answer test vectors in
[tests/kat.rs](../tests/kat.rs). Any code change that flips a KAT
vector is, by definition, a determinism break.

Tier 2 and Tier 3 are **explicitly non-deterministic** — Tier 2
mixes in PID and wall-clock time; Tier 3 reads from the OS CSPRNG.
Neither makes any reproducibility claim.

## Deprecation policy

A symbol marked `#[deprecated]` in a `1.x.Y` release:

- Remains callable for the entire `1.x` line.
- Continues to behave per its documented contract.
- May only be removed in a `2.0.0` release.

Deprecation is for guidance, not removal. Code that compiles against
`1.0.0` must continue to compile against `1.x.LATEST` (modulo the
deprecation warning), without source changes.

## What is NOT covered

The stability contract does NOT cover:

- **Internal performance characteristics.** A `1.x.Y` may make any
  operation faster or slower than `1.0.0`, so long as it remains
  within an order of magnitude of the documented per-tier target
  (Tier 1: ~1 ns/u64; Tier 2: <100 ns/call; Tier 3: one syscall).
  Documented benchmark numbers in the README are illustrative, not
  contractual.
- **Internal types and modules.** Any item not re-exported through
  `lib.rs` is internal and may move or change between minor releases.
- **Exact wording of error messages and panic messages.** The error
  *kind* (`io::Error::kind()`) and the fact that a given input panics
  are part of the contract; the human-readable text is not.
- **Compile-time errors that depend on call patterns.** If a future
  Rust version's type inference rejects an `mod_rand::tier1::*` call
  that compiled under the MSRV, that may need to be addressed in a
  patch release; it does not constitute a stability break.

## Dependencies

Zero runtime dependencies outside of `std` (when `std` feature is
enabled). This is a hard architectural property, not just a current
state — adding any external dependency to the `[dependencies]` table
of `Cargo.toml` requires a `2.0.0` bump.

The point: `mod-rand` exists partly to break the
`getrandom`-induced MSRV ratchet. Adding a dep would defeat the
purpose.

## MSRV

`1.0.0` ships with MSRV `1.75.0`. Any change to the MSRV is a
minor-version bump minimum.

Recent or upcoming Rust features the crate does **not** use, to keep
the MSRV low:

- `let_chains` (1.88)
- The `OptionExt::is_some_and` family (1.70 — predates MSRV anyway)
- Inline `const {...}` expressions (1.79)

If a future internal optimisation requires a newer language feature,
the change goes into the next minor release with an MSRV bump.

## Feature flags

The default feature set is `["std", "tier2", "tier3"]`. Removing any
feature from this set, or adding a new default feature, requires a
major version bump (it's a breaking change for users who pin features
explicitly).

Adding a non-default feature is a minor bump. Renaming a feature is
a major bump.

## Reporting a stability break

If you encounter what looks like a `1.x` stability break:

1. Run the failing case against the latest patch release of `1.x` to
   confirm reproducibility.
2. Capture the exact `seed`, API call sequence, and output values that
   differ between releases.
3. Open an issue at
   <https://github.com/jamesgober/mod-rand/issues>
   with the repro and a link to your KAT-style vectors.

Stability breaks are bugs and are fixed in the next patch release.
