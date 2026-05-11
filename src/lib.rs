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
//! ```
//! use mod_rand::tier1::Xoshiro256;
//!
//! let mut rng = Xoshiro256::seed_from_u64(42);
//! let n: u64 = rng.next_u64();
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
//! `v0.1.0` is a placeholder release. Real implementation lands in
//! `0.9.x`. See the [CHANGELOG](https://github.com/jamesgober/mod-rand/blob/main/CHANGELOG.md)
//! for what's stable.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod tier1;

#[cfg(feature = "tier2")]
pub mod tier2;

#[cfg(feature = "tier3")]
pub mod tier3;
