//! # mod-rand
//!
//! Tiered random number generation for Rust. Zero dependencies. Pick
//! the tier appropriate to your threat model.
//!
//! ## Tiers
//!
//! - **[`tier1`]**: Deterministic seedable PRNG (xoshiro256\*\*).
//!   For simulation, fixture data, non-security shuffling. Always
//!   available, works in `no_std`.
//! - **[`tier2`]**: Process-unique seeds derived from PID + time +
//!   counter. For tempdir names, request IDs, log correlation. Fast
//!   enough for high-frequency use. Not cryptographic.
//! - **[`tier3`]**: OS-backed cryptographic random. For tokens, keys,
//!   session IDs. Calls platform syscalls directly.
//!
//! ## Quick example
//!
//! Raw draws:
//!
//! ```
//! use mod_rand::tier1::Xoshiro256;
//!
//! let mut rng = Xoshiro256::seed_from_u64(42);
//! let n: u64 = rng.next_u64();
//! # let _ = n;
//! ```
//!
//! Bounded ranges — every tier exposes a parallel `gen_range_*` /
//! `range_*` / `random_range_*` family that uses Lemire's "Nearly
//! Divisionless" rejection sampling under the hood, so output is
//! uniformly distributed with no modulo bias:
//!
//! ```
//! use mod_rand::tier1::Xoshiro256;
//!
//! let mut rng = Xoshiro256::seed_from_u64(42);
//!
//! // Half-open: never returns 100.
//! let pct: u32 = rng.gen_range_u32(0..100);
//!
//! // Inclusive: classic six-sided die.
//! let d6: u32 = rng.gen_range_inclusive_u32(1..=6);
//! # let _ = (pct, d6);
//! ```
//!
//! The same `..` (half-open) vs `..=` (inclusive) convention applies
//! on Tier 2 (free functions) and Tier 3 (free functions returning
//! `io::Result`):
//!
//! ```no_run
//! # #[cfg(all(feature = "tier2", feature = "tier3"))]
//! # fn demo() -> std::io::Result<()> {
//! use mod_rand::{tier2, tier3};
//!
//! let id  = tier2::range_inclusive_u32(1..=1_000);
//! let key = tier3::random_range_inclusive_u64(0..=u64::MAX)?;
//! # let _ = (id, key);
//! # Ok(())
//! # }
//! ```
//!
//! ## Choosing a tier
//!
//! | Use case                          | Tier |
//! |-----------------------------------|------|
//! | Test fixtures, simulation         | 1    |
//! | Tempdir names, request IDs        | 2    |
//! | Auth tokens, session IDs, keys    | 3    |
//!
//! ## Status
//!
//! The `0.9.x` line ships the real algorithms: full xoshiro256\*\*
//! with splitmix64 seeding (Tier 1), Stafford-mix-13 over (PID +
//! nanos + atomic counter + per-process salt) (Tier 2), and direct
//! platform syscalls for Tier 3 (`getrandom(2)` / `BCryptGenRandom` /
//! `getentropy(3)`). All bounded-range methods use Lemire's
//! "Nearly Divisionless" rejection sampling, verified for uniformity
//! by 1,000,000-draw chi-squared tests at the integration level.
//! The API is stable through the `0.9.x` series; `1.0` will pin it.
//! See the [CHANGELOG](https://github.com/jamesgober/mod-rand/blob/main/CHANGELOG.md)
//! for release history.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod tier1;

#[cfg(feature = "tier2")]
pub mod tier2;

#[cfg(feature = "tier3")]
pub mod tier3;
