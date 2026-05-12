<h1 align="center">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
  <br>
  <code>mod-rand</code>
  <br>
  <sup>
    <sub>TIERED RANDOM NUMBER GENERATION FOR RUST</sub>
  </sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/mod-rand"><img alt="crates.io" src="https://img.shields.io/crates/v/mod-rand.svg"></a>
    <a href="https://crates.io/crates/mod-rand"><img alt="downloads" src="https://img.shields.io/crates/d/mod-rand.svg"></a>
    <a href="https://docs.rs/mod-rand"><img alt="docs.rs" src="https://docs.rs/mod-rand/badge.svg"></a>
    <a href="https://github.com/jamesgober/mod-rand/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/mod-rand/actions/workflows/ci.yml/badge.svg"></a>
</p>

<p align="center">
    Fast PRNG, process-unique seeds, and OS-backed cryptographic random<br>
    in one zero-dependency library. Pick the tier appropriate to your threat model.
</p>

---

## What it does

Random number generation in Rust today forces a choice: pull in the
heavy `rand` ecosystem (multiple crates, opinionated traits, generic
overhead) or write your own. `mod-rand` is the middle ground — three
clearly-tiered random sources in one library, zero external
dependencies, MSRV 1.75.

## The three tiers

```rust
use mod_rand::{tier1, tier2, tier3};

// Tier 1: Fast deterministic PRNG — for simulations and test fixtures.
let mut rng = tier1::Xoshiro256::seed_from_u64(42);
let n: u64 = rng.next_u64();

// Tier 2: Process-unique seeds — for tempdir names and request IDs.
let name: String = tier2::unique_name(8);

// Tier 3: Cryptographic random — for tokens and keys.
let token: String = tier3::random_hex(16)?;
# Ok::<(), std::io::Error>(())
```

| Tier | Algorithm | Use case | Crypto-safe |
|------|-----------|----------|-------------|
| 1 | xoshiro256\*\* | Simulation, fixtures, shuffling | No |
| 2 | PID + nanos + counter mix | Tempdir names, request IDs | No |
| 3 | OS syscall (`getrandom`/`BCryptGenRandom`/`getentropy`) | Tokens, keys, session IDs | Yes |

## Why this library exists

- **Zero dependencies.** No `rand`, no `getrandom` crate, no `libc`.
  Just `std`. Tier 1 even works in `no_std`.
- **Explicit threat model.** You pick the tier; you know what
  guarantees you're getting.
- **Lower MSRV than the alternatives.** Works on Rust 1.75; many
  random crates today require 1.85+.
- **Fast.** Tier 1 is ~1ns/u64. Tier 2 is ~50ns. Tier 3 is one
  syscall.

## Feature flags

```toml
[dependencies]
mod-rand = { version = "0.1", default-features = false }   # tier1 only, no_std
mod-rand = { version = "0.1", features = ["tier2"] }       # + process-unique
mod-rand = "0.1"                                            # all three tiers (default)
```

## Status

`v0.1.0` is the name-claim release with placeholder implementations.
Real algorithms (full xoshiro256\*\*, splitmix64 seeding, platform
syscalls) land in `0.9.x`. **Do not use the cryptographic tier from
`v0.1.0` for security-sensitive work** — the placeholder is not
cryptographically secure.

## Minimum supported Rust version

`1.75` — pinned in `Cargo.toml` and verified by CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
