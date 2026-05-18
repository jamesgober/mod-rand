# mod-rand vs. the Rust randomness ecosystem

> Honest side-by-side: when mod-rand is the right choice, and when one
> of the alternatives is.

`mod-rand` is one of several randomness crates available on
crates.io. The headline tradeoffs:

| Choosing between... | If you want...                                                | Pick                  |
|---------------------|---------------------------------------------------------------|-----------------------|
| `mod-rand` vs `rand`      | Distributions (Normal, Gamma, etc.), generic `Rng` trait | `rand` + `rand_distr` |
| `mod-rand` vs `rand`      | Zero deps, fixed MSRV 1.75, explicit tier model     | `mod-rand`            |
| `mod-rand` vs `fastrand`  | A single fast PRNG, minimal API                     | `fastrand`            |
| `mod-rand` vs `fastrand`  | Cryptographic random plus a fast PRNG, same library | `mod-rand`            |
| `mod-rand` vs `nanorand`  | A pure-Rust PRNG family, optionally `no_std`        | Both work — see below |
| `mod-rand` vs `nanorand`  | OS-backed crypto random in the same crate           | `mod-rand`            |

The rest of this document expands on each comparison.

---

## `mod-rand` vs `rand`

[`rand`](https://crates.io/crates/rand) is the de facto Rust randomness
crate: a `RngCore` trait, many generator implementations, a generic
`Rng` extension trait, a sibling `rand_distr` for distributions, and
deep integration with `getrandom` for OS entropy.

### Things `rand` does that `mod-rand` doesn't

- **Named distributions.** Normal, Gamma, Beta, Poisson, Exponential,
  StudentT, ChiSquared, and many others, via `rand_distr`. `mod-rand`
  intentionally stops at uniform + Bernoulli.
- **Generic `Rng` trait.** `rand::Rng::gen::<T>()` works for any `T`
  that implements `Standard`. `mod-rand` exposes concrete types — you
  call `rng.next_u64()`, `rng.gen_range_u64(0..N)`, etc., not a generic
  `gen::<T>()`.
- **Ecosystem integration.** Crates across the Rust ecosystem use the
  `rand::Rng` trait in their public APIs. If you need to *pass* a
  random source to another crate that accepts an `Rng`, you need
  `rand` (or an adapter).
- **More algorithms.** ChaCha20, PCG, ChaCha8Rand, etc. `mod-rand`
  ships exactly one PRNG (xoshiro256**), exactly one process-unique
  source, and exactly one OS-CSPRNG path. Each chosen for a specific
  niche; no menu.
- **Wider numeric type coverage on derived methods.** `rand` can fill
  any `T: Standard` (BigInts, fixed-size SIMD types, etc.). `mod-rand`
  covers the 12 primitive integer widths plus `f32`/`f64`/`bool`.

### Things `mod-rand` does that `rand` doesn't

- **Zero runtime dependencies.** Just `std`. The full default-features
  `cargo tree` for `mod-rand` is one node deep.
- **Lower MSRV.** `mod-rand` is `1.75`. As of this writing, `rand`
  itself ships with a higher MSRV (and `getrandom`, transitively, has
  ratcheted the effective floor higher still on multiple occasions).
- **Explicit tier model.** With `rand` the threat-model story is split
  across multiple crates and types (`thread_rng()` vs `OsRng` vs
  `SmallRng` vs `StdRng`). With `mod-rand` the three tiers are a
  single import statement: `use mod_rand::{tier1, tier2, tier3}`.
- **Tier 2 niche.** `rand` has no direct equivalent of Tier 2's
  process-unique-with-monotonic-counter primitive — the closest is
  manually combining PID + nanos + atomic counter yourself. mod-rand
  ships this as a first-class operation.
- **Determinism contract.** mod-rand's Tier 1 is locked under SemVer
  to produce byte-for-byte identical output for a given seed + call
  sequence for the entire `1.x` line (see [STABILITY.md](STABILITY.md)).
  `rand`'s analogous stability is documented case-by-case per
  `RngCore` impl and has historically been more flexible across major
  versions.
- **Embedded `String` generation.** `gen_alphanumeric`, `gen_hex`, and
  the `random_string` / `random_alphanumeric` families across tiers.
  In `rand` this is a `rand::distributions::Alphanumeric` adapter
  pipeline; in mod-rand it's one method call.

### Headline numbers, side by side

The closest comparison points (measured on the same Ryzen 9 9950X3D /
Windows 11 box used elsewhere in this document):

| Operation                              | `mod-rand`     | `rand` 0.8.x (reference)  |
|----------------------------------------|----------------|---------------------------|
| Single `u64`, fast PRNG                | ~0.6 ns        | ~1.5 ns (Xoshiro256Plus)  |
| `u64` in bounded range `0..100`        | ~0.9 ns        | ~1.6 ns (Uniform)         |
| Cryptographic `u64`                    | ~35 ns (Win)   | ~40 ns (OsRng)            |
| 32 cryptographic bytes                 | ~53 ns (Win)   | ~60 ns (OsRng)            |

`rand` numbers above are illustrative; actual `rand` performance varies
by version, RNG choice, and platform. Run your own benchmarks before
making a decision based on these.

The takeaway: mod-rand isn't a `rand` replacement for users who lean
on `rand_distr` or pass generic `Rng` references around — it's an
alternative for users whose needs are well-served by three concrete
primitives in zero deps.

---

## `mod-rand` vs `fastrand`

[`fastrand`](https://crates.io/crates/fastrand) is a single-PRNG crate
with a tight, opinionated API and minimal dependencies.

### What `fastrand` does that `mod-rand` doesn't

- **Even fewer concepts.** `fastrand::u64()`, `fastrand::usize(..)`,
  `fastrand::shuffle(..)` — global thread-local state, no `Rng` value
  to thread through your code.
- **Smaller binary footprint.** `fastrand` is smaller and simpler.
  `mod-rand` ships three tiers of code, only one of which (Tier 1) is
  in scope for the comparison.
- **Slightly faster for the simplest case.** Both use rejection
  sampling, both expose `gen_range`-style APIs; in microbenchmarks
  they're within 10–20% of each other for raw draws.

### What `mod-rand` does that `fastrand` doesn't

- **Cryptographic random in the same library.** `fastrand` makes no
  attempt at OS entropy; you need a separate dependency for that.
- **Process-unique values.** Tier 2's monotonic counter +
  PID + nanosecond mix gives a guarantee `fastrand` doesn't try to
  make.
- **Reproducibility contract.** mod-rand's Tier 1 is byte-stable
  across the `1.x` line by spec. `fastrand`'s algorithm has changed
  between major versions; reproducibility is best-effort.
- **128-bit integer ranges.** mod-rand's `gen_range_u128` /
  `gen_range_i128` are part of the standard API. `fastrand` doesn't
  cover 128-bit widths.
- **Owned generator, not just thread-local globals.** `mod-rand`'s
  `Xoshiro256` is a value you hold and pass. You can clone it,
  checkpoint its state, jump it forward by 2^128 calls — none of
  which `fastrand`'s global-only model offers.

If you just need *one* fast PRNG and you don't care about determinism
across major versions, `fastrand` is excellent. If you need any of
the other tiers, you'd be pulling in `fastrand` + something else;
`mod-rand` ships all three.

---

## `mod-rand` vs `nanorand`

[`nanorand`](https://crates.io/crates/nanorand) is a small,
`no_std`-friendly crate covering several PRNGs (wyrand, chacha,
pcg64) plus a basic shuffle.

### What `nanorand` does that `mod-rand` doesn't

- **Multiple PRNG algorithms.** wyrand, chacha8/12/20, pcg64. mod-rand
  ships just xoshiro256**.
- **A documented ChaCha20-based cryptographic source.** `nanorand`'s
  `chacha::ChaCha20` is a userspace stream cipher seeded from
  `getrandom`. This is a different threat model than mod-rand Tier 3:
  Tier 3 hits the kernel on every call (no userspace state to leak on
  fork / VM resume). `nanorand` is faster in the common case but
  needs `getrandom` for seeding.
- **`no_std + alloc`-friendly out of the box.** mod-rand's Tier 1 is
  `no_std` for the raw stream + bounded ranges; its string methods
  require `std`.

### What `mod-rand` does that `nanorand` doesn't

- **Direct OS syscall for crypto random.** No `getrandom` crate as
  a dependency; mod-rand declares the platform syscalls
  (`getrandom(2)`, `getentropy(3)`, `BCryptGenRandom`) inline.
- **Three tiers in one crate.** `nanorand` covers Tier 1's analogue
  via wyrand/pcg64 and offers ChaCha-seeded random. The
  process-unique tier (Tier 2) has no `nanorand` analogue.
- **A full collection-ops surface.** `nanorand` has `shuffle`. mod-rand
  has `shuffle`, `sample` (without replacement), `weighted_index`,
  and `weighted_choice`.
- **128-bit integer ranges.** Same point as in the `fastrand`
  comparison.
- **Reproducibility contract.** Both crates document determinism for
  their PRNGs, but mod-rand's `1.x` line pins it byte-for-byte under
  SemVer (see [STABILITY.md](STABILITY.md)).

If you need ChaCha20 specifically (e.g., for a documented
cryptographic stream cipher), `nanorand` has it directly and
mod-rand doesn't (it's not in scope for `1.x`; if demand surfaces
it's a candidate for a later minor release as a new operation, not
a new tier).

---

## Honest non-strengths of `mod-rand`

The two cases where `mod-rand` is clearly *not* the right choice:

1. **You need distributions.** If you're doing simulation work that
   pulls Normal, Gamma, Beta, or any other named distribution,
   `rand_distr` is what you want. `mod-rand` provides the raw uniform
   stream you'd build distributions on top of, but the named
   distributions themselves are out of scope.

2. **You need ecosystem interop.** If you're integrating with another
   crate that takes an `&mut impl rand::Rng` argument, you need
   `rand`. There is no `Xoshiro256: rand::Rng` impl in `mod-rand`
   (that would re-introduce the `rand` dep). If this matters, an
   external adapter crate is the right pattern.

If neither of those applies, the trade is: `mod-rand` gives you a
zero-dep, tier-explicit, version-locked surface across numbers +
bytes + strings + tokens + collection ops. Most application code that
reaches for "I need a random thing" lives comfortably inside that
surface.
