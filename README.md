<h1 align="center">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
  <br>
  <code>mod-rand</code>
  <br>
  <sup>
    <sub>TIERED RANDOMNESS FOR RUST</sub>
  </sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/mod-rand"><img alt="crates.io" src="https://img.shields.io/crates/v/mod-rand.svg"></a>
    <a href="https://crates.io/crates/mod-rand"><img alt="downloads" src="https://img.shields.io/crates/d/mod-rand.svg"></a>
    <a href="https://docs.rs/mod-rand"><img alt="docs.rs" src="https://docs.rs/mod-rand/badge.svg"></a>
    <img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.75%2B-blue.svg?style=flat-square" title="Rust Version">
    <a href="https://github.com/jamesgober/mod-rand/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/mod-rand/actions/workflows/ci.yml/badge.svg"></a>
</p>

<p align="center">
    Numbers, bytes, strings, tokens, and collection ops (shuffle, sample,<br>
    weighted choice) at three explicit threat-model tiers — one zero-dependency library.
</p>

---

## What it is

`mod-rand` is a tiered **randomness** library for Rust. Three concrete
random sources, each chosen to be excellent for one threat model;
every operation you'd reach for — bounded integer ranges, byte
buffers, hex tokens, random or process-unique strings, shuffles,
samples, and weighted choice — exposed at the appropriate tier.

Zero runtime dependencies. MSRV `1.75`. API locked under SemVer
for the entire `1.x` line.

```rust
use mod_rand::tier1::Xoshiro256;
use mod_rand::{tier2, tier3};

// Tier 1 — fast deterministic PRNG (xoshiro256**). Reproducible from a seed.
let mut rng = Xoshiro256::seed_from_u64(42);
let n: u64       = rng.next_u64();
let pct: u32     = rng.gen_range_u32(0..100);
let label: String = rng.gen_alphanumeric(16); // reproducible, never a secret

// Tier 2: process-unique values. Request IDs, log correlation.
let id: String = tier2::unique_name(12);

// Tier 3 — OS-backed cryptographic random. Tokens, keys, session IDs.
let secret: String = tier3::random_hex(32)?;
# Ok::<(), std::io::Error>(())
```

## What it covers

Every category of randomness operation that's in scope, at every tier
where it makes sense.

| Operation                              | Tier 1 (PRNG)      | Tier 2 (process-unique) | Tier 3 (crypto) |
|----------------------------------------|--------------------|--------------------------|-----------------|
| Raw `u32` / `u64` draws                | `next_u32` / `next_u64` | `unique_u64`            | `random_u32` / `random_u64` |
| Fill a `&mut [u8]`                     | `fill_bytes`       | —                        | `fill_bytes`     |
| Bounded integer ranges (every width)   | `gen_range_*`      | `range_*`                | `random_range_*` |
| 128-bit integer ranges                 | `gen_range_u128` / `i128` | `range_u128` / `i128` | `random_range_u128` / `i128` |
| Uniform `f64` / `f32`                  | `gen_f64` / `gen_f32` / `next_f64` | —                | —               |
| Bernoulli trial                        | `gen_bool(p)`      | —                        | —               |
| Hex strings                            | `gen_hex(len)`     | `unique_hex(len)`        | `random_hex(bytes)` / `random_hex_string(len)` |
| Alphanumeric strings                   | `gen_alphanumeric` | `unique_name`            | `random_alphanumeric` |
| Arbitrary-charset strings              | `gen_string`       | (deprecated)             | `random_string` |
| Base32 / base58 / base64 / URL-safe    | via `charsets::*`  | via `charsets::*`        | via `charsets::*` |
| Shuffle a `&mut [T]`                   | `shuffle`          | —                        | `shuffle`        |
| Sample `k` without replacement         | `sample`           | —                        | —               |
| Weighted choice                        | `weighted_choice` / `weighted_index` | —          | —               |
| Stream splitting (`2^128` / `2^192`)   | `jump` / `long_jump` | —                      | —               |

Tier 1 is `no_std`-compatible for everything that doesn't require
allocation. Tier 2 and Tier 3 require `std` (default feature).

## The three tiers

Pick by threat model, not by speed.

| Tier | Algorithm | Use case | Crypto-safe |
|------|-----------|----------|-------------|
| 1 | xoshiro256\*\* (splitmix64-seeded) | Simulation, fixtures, shuffling, non-security strings | No |
| 2 | PID + nanos + atomic counter + Stafford-mix-13 | Request IDs, log correlation IDs, names in private directories | No |
| 3 | OS syscall (`getrandom` / `BCryptGenRandom` / `getentropy`) | Tokens, passwords, keys, session IDs, salts, temp names in shared directories | Yes |

Each tier is also reachable under a plain name: `mod_rand::secure`
(tier 3), `mod_rand::unique` (tier 2) and `mod_rand::seeded`
(tier 1). They are the same modules.

Tier 1 and tier 2 output is predictable. Never use either for a
token, a password, a key, or a temp name in a shared directory such
as `/tmp`, where another user could create the next name first.

| Question                                           | Tier |
|----------------------------------------------------|------|
| Is the value reproducible from a seed?             | 1    |
| Must two calls inside one process differ (not secret)? | 2 |
| Could an attacker benefit from predicting it?      | 3    |

If the answer to the third question is "yes" — even maybe — use Tier 3.

## Bounded ranges — every integer width

Every tier exposes `gen_range_*` / `range_*` / `random_range_*`
methods using Rust's range syntax. `..` is half-open, `..=` is
inclusive; the caller's choice is the contract. All bounded methods
use **Daniel Lemire's "Nearly Divisionless"** rejection sampling, so
output is uniformly distributed — no modulo bias.

Widths covered: `u8`, `u16`, `u32`, `u64`, `u128`, `usize`, and the
signed counterparts.

```rust
use mod_rand::tier1::Xoshiro256;
use mod_rand::{tier2, tier3};

let mut rng = Xoshiro256::seed_from_u64(42);

let byte: u8   = rng.gen_range_inclusive_u8(0..=255);
let pct:  u32  = rng.gen_range_u32(0..100);
let big:  u128 = rng.gen_range_u128(0..(u128::MAX / 2));
let die:  u32  = rng.gen_range_inclusive_u32(1..=6);   // classic d6

let id     = tier2::range_inclusive_u32(1..=1_000);
let secret = tier3::random_range_inclusive_u64(0..=u64::MAX)?;
# Ok::<(), std::io::Error>(())
```

The 128-bit ranges generalise Lemire's algorithm to a 256-bit
intermediate via two `u64` draws; the full-width inclusive
`0..=u128::MAX` is special-cased to a raw 128-bit reinterpret.

## String generation

Custom charset, or a pick from the standard ones in
[`mod_rand::charsets`](https://docs.rs/mod-rand/latest/mod_rand/charsets/index.html).

```rust
use mod_rand::tier1::Xoshiro256;
use mod_rand::{charsets, tier2, tier3};

let mut rng = Xoshiro256::seed_from_u64(1);

// Tier 1 — deterministic from the seed.
let id    = rng.gen_alphanumeric(16);
let hex   = rng.gen_hex(32);
let pin   = rng.gen_numeric(6);

// Custom charset — pick from charsets:: or supply your own &[u8].
let url   = rng.gen_string(24, charsets::URL_SAFE);
let coin  = rng.gen_string(20, charsets::BASE58);

// Tier 2: process-unique IDs. Predictable, never a token.
let name  = tier2::unique_name(13);             // request or log ID

// Tier 3: cryptographic. Tokens, passwords, keys.
let token = tier3::random_alphanumeric(32)?;
# Ok::<(), std::io::Error>(())
```

Charset constants in `mod_rand::charsets`: `ALPHANUMERIC`, `ALPHA`,
`ALPHA_LOWER`, `ALPHA_UPPER`, `NUMERIC`, `HEX_LOWER`, `HEX_UPPER`,
`URL_SAFE` (RFC 4648 §5), `BASE58` (Bitcoin alphabet), `BASE64`
(RFC 4648 §4). Custom charsets are accepted as `&[u8]`; non-ASCII
charsets are rejected (panic on Tier 1 / Tier 2; `InvalidInput` on
Tier 3) so the returned `String` is always valid UTF-8.

## Collection operations

Fisher-Yates shuffle, sample-without-replacement, and weighted
choice. Available on Tier 1 (deterministic, reproducible) and
Tier 3 shuffle (cryptographic).

```rust
use mod_rand::tier1::Xoshiro256;
use mod_rand::tier3;

let mut rng = Xoshiro256::seed_from_u64(1);

// Shuffle in place. Uniform over all n! permutations.
let mut hand: Vec<u8> = (0..52).collect();
rng.shuffle(&mut hand);

// Sample k references without replacement, in source-slice order.
let pool: Vec<&str> = vec!["alice", "bob", "carol", "dave", "erin"];
let chosen: Vec<&&str> = rng.sample(&pool, 2);

// Weighted choice over a probability vector.
let items   = ["common", "uncommon", "rare", "epic"];
let weights = [70.0, 20.0, 8.0, 2.0];
let drop    = rng.weighted_choice(&items, &weights).unwrap();

// Cryptographic shuffle — every permutation drawn from the OS CSPRNG.
let mut deck: Vec<u8> = (0..52).collect();
tier3::shuffle(&mut deck)?;
# Ok::<(), std::io::Error>(())
```

## Performance

Measured on a Ryzen 9 9950X3D, Windows 11 (`cargo bench`):

**Tier 1 — xoshiro256\*\* (target ~1 ns/u64)**

| op                                              | time      |
|-------------------------------------------------|-----------|
| `next_u64`                                      | ~0.6 ns   |
| `next_f64` / `gen_f64`                          | ~0.7 ns   |
| `gen_f32`                                       | ~0.7 ns   |
| `gen_bool(0.5)`                                 | ~0.8 ns   |
| `fill_bytes(32)`                                | ~2.0 ns   |
| `gen_range_u64(0..100)`                         | ~0.8 ns   |
| `gen_range_inclusive_u32(1..=6)` (d6)           | ~0.9 ns   |
| `gen_range_u8(0..100)`                          | ~0.8 ns   |
| `gen_range_u128(0..u128::MAX/2)`                | ~2.2 ns   |
| `gen_range_inclusive_u128(0..=u128::MAX)`       | ~1.1 ns   |
| `gen_range_u64(0..⅔·u64::MAX)` worst-case       | ~5.9 ns   |
| `gen_alphanumeric(16)`                          | ~58 ns    |
| `gen_alphanumeric(64)`                          | ~115 ns   |
| `gen_hex(32)`                                   | ~63 ns    |
| `shuffle(10)`                                   | ~10 ns    |
| `shuffle(100)`                                  | ~104 ns   |
| `shuffle(1000)`                                 | ~953 ns   |
| `shuffle(10000)`                                | ~9.5 µs   |
| `sample(k=10, n=1000)`                          | ~905 ns   |
| `weighted_index(10 weights)`                    | ~19 ns    |
| `weighted_index(100 weights)`                   | ~172 ns   |
| `weighted_index(1000 weights)`                  | ~1.1 µs   |

**Tier 2 — process-unique (dominated by `SystemTime::now()`)**

| op                                              | time      |
|-------------------------------------------------|-----------|
| `unique_u64`                                    | ~21 ns    |
| `unique_name(8)`                                | ~42 ns    |
| `unique_hex(16)`                                | ~47 ns    |
| `range_u64(0..100)`                             | ~23 ns    |
| `range_u128(0..u128::MAX/2)`                    | ~45 ns    |
| `random_alphanumeric(16)`                       | ~420 ns   |

**Tier 3 — OS CSPRNG (Windows / `BCryptGenRandom`)**

| op                                              | time      |
|-------------------------------------------------|-----------|
| `random_u64`                                    | ~35 ns    |
| `fill_bytes(32)`                                | ~53 ns    |
| `fill_bytes(1024)`                              | ~224 ns   |
| `random_hex(16)`                                | ~97 ns    |
| `random_range_u64(0..100)`                      | ~35 ns    |
| `random_range_u128(0..u128::MAX/2)`             | ~48 ns    |
| `random_alphanumeric(16)`                       | ~628 ns   |
| `random_alphanumeric(64)`                       | ~2.4 µs   |
| `shuffle(52)` (deck of cards)                   | ~1.9 µs   |
| `shuffle(1000)`                                 | ~38 µs    |

Tier 1 beats its 1 ns/u64 target. Linux / macOS Tier 3 numbers are
kernel-dependent; expect 100–500 ns per call on commodity hardware.

## Why this library exists

- **Zero dependencies.** No `rand`, no `getrandom` crate, no `libc`.
  Just `std`. Tier 1 works in `no_std`.
- **Explicit threat model.** You pick the tier; you know what
  guarantees you're getting.
- **Lower MSRV than the alternatives.** `1.75`. Many random crates
  in the ecosystem require `1.85+`.
- **Determinism contract on Tier 1.** Locked byte-for-byte under
  SemVer for the entire `1.x` line — see
  [`docs/STABILITY.md`](docs/STABILITY.md).
- **One library, three tiers, every operation.** Numbers, bytes,
  strings, tokens, shuffle, sample, weighted choice. You don't need
  `rand` + `rand_distr` + `fastrand` + a hand-rolled crypto random.

## How it compares

Honest, side-by-side. The full discussion (including non-strengths)
is in [`docs/COMPARISON.md`](docs/COMPARISON.md).

|                              | `mod-rand` | `rand` + `rand_distr` | `fastrand` | `nanorand` |
|------------------------------|------------|-----------------------|------------|------------|
| Fast PRNG                    | ✓ Tier 1   | ✓ many                | ✓          | ✓ many     |
| OS cryptographic random      | ✓ Tier 3   | ✓ via `getrandom`     | ✗          | ✓ ChaCha20 (userspace) |
| Process-unique stream        | ✓ Tier 2   | partial (build yourself) | ✗       | ✗          |
| 128-bit integer ranges       | ✓          | ✓                     | ✗          | ✗          |
| String generation in API     | ✓          | via `Alphanumeric`    | ✗          | ✗          |
| Shuffle / sample / weighted  | ✓          | ✓                     | shuffle    | shuffle    |
| Named distributions          | ✗          | ✓ (`rand_distr`)      | ✗          | ✗          |
| Generic `Rng` trait          | ✗          | ✓                     | ✗          | partial    |
| Runtime crate dependencies   | **0**      | several (`getrandom`, etc.) | 0+ | 0+         |
| MSRV (at time of writing)    | **1.75**   | higher                | 1.61       | 1.65       |

Use `mod-rand` when its tier model fits and you want zero deps + a
locked API. Reach for `rand` if you need named distributions or
generic-trait ecosystem interop.

## Feature flags

```toml
[dependencies]
mod-rand = { version = "1.0", default-features = false }   # tier1 only, no_std
mod-rand = { version = "1.0", features = ["tier2"] }       # + tier2
mod-rand = "1.0"                                             # all three tiers (default)
```

| Feature  | Effect                                                         |
|----------|----------------------------------------------------------------|
| `std`    | Required by `tier2`, `tier3`, and string generation on `tier1` |
| `tier2`  | Enables `mod_rand::tier2`                                      |
| `tier3`  | Enables `mod_rand::tier3`                                      |

Default features: `["std", "tier2", "tier3"]`.

## Documentation

- [docs/API.md](docs/API.md) — hand-written API reference, tier by tier.
- [docs/STABILITY.md](docs/STABILITY.md) — SemVer policy, determinism
  contract, deprecation rules.
- [docs/COMPARISON.md](docs/COMPARISON.md) — side-by-side with `rand`,
  `fastrand`, `nanorand`.
- [docs/API-FREEZE-AUDIT.md](docs/API-FREEZE-AUDIT.md) — full manifest
  of every `1.0` public symbol.
- [CHANGELOG.md](CHANGELOG.md) — release history.

## Minimum supported Rust version

`1.75` — pinned in `Cargo.toml`, verified by CI on every change. An
MSRV bump is a minor-version bump minimum.

## License

Apache-2.0. See [LICENSE](LICENSE).


<!-- COPYRIGHT
---------------------------------->
<div align="center">
  <br>
  <h2></h2>
  Copyright &copy; 2026 James Gober.
</div>
