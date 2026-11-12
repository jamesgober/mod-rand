//! # mod-rand
//!
//! Tiered random number generation for Rust. Zero dependencies. Pick
//! the tier appropriate to your threat model.
//!
//! ## Tiers
//!
//! Each tier is also available under a plain name. The plain names
//! are the same modules, so mixing them is fine.
//!
//! - **[`secure`]** (same as [`tier3`]): OS-backed cryptographic
//!   random. The only choice for tokens, passwords, keys, session
//!   IDs, and temp names in shared directories. Calls platform
//!   syscalls directly.
//! - **[`unique`]** (same as [`tier2`]): process-unique values derived
//!   from PID + time + counter. For request IDs, log correlation, and
//!   names in private directories. Fast enough for high-frequency use.
//!   Predictable, so never a token or a password.
//! - **[`seeded`]** (same as [`tier1`]): deterministic seedable PRNG
//!   (xoshiro256\*\*). For simulation, fixture data, non-security
//!   shuffling. Always available, works in `no_std`. Reproducible
//!   from its seed, so never a token or a password.
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
//! | Use case                                         | Module              |
//! |--------------------------------------------------|---------------------|
//! | Test fixtures, simulation                        | `seeded` (tier 1)   |
//! | Request IDs, names in a private directory        | `unique` (tier 2)   |
//! | Tokens, passwords, session IDs, keys, salts      | `secure` (tier 3)   |
//! | Temp file or directory names in `/tmp`           | `secure` (tier 3)   |
//!
//! If an attacker could gain anything by predicting the value, use
//! `secure`.
//!
//! ```
//! # #[cfg(feature = "tier3")]
//! # fn demo() -> std::io::Result<()> {
//! let token = mod_rand::secure::random_alphanumeric(32)?;
//! let key = mod_rand::secure::random_bytes(32)?;
//! # let _ = (token, key);
//! # Ok(())
//! # }
//! ```
//!
//! ## Status
//!
//! `1.x` is API-stable under SemVer: full xoshiro256\*\* with
//! splitmix64 seeding (tier 1), Stafford-mix-13 over (PID + nanos +
//! atomic counter + per-process salt) (tier 2), and direct platform
//! syscalls for tier 3 (`getrandom(2)` / `BCryptGenRandom` /
//! `getentropy(3)`). All bounded-range methods use Lemire's
//! "Nearly Divisionless" rejection sampling, verified for uniformity
//! by 1,000,000-draw chi-squared tests at the integration level.
//! See the [CHANGELOG](https://github.com/jamesgober/mod-rand/blob/main/CHANGELOG.md)
//! for release history.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod charsets;
pub mod tier1;

#[cfg(feature = "tier2")]
pub mod tier2;

#[cfg(feature = "tier3")]
pub mod tier3;

/// OS-backed cryptographic random: the same module as [`tier3`].
///
/// The plain name for the tier to use for tokens, passwords, keys,
/// session IDs, salts, and names in shared directories.
///
/// ```
/// let token = mod_rand::secure::random_hex(16)?;
/// assert_eq!(token.len(), 32);
/// # Ok::<(), std::io::Error>(())
/// ```
#[cfg(feature = "tier3")]
#[cfg_attr(docsrs, doc(cfg(feature = "tier3")))]
pub mod secure {
    pub use crate::tier3::*;
}

/// Process-unique values: the same module as [`tier2`].
///
/// Predictable to anyone who has seen earlier values, so never a
/// token, a password, or a key; see [`tier2`] for what it is good for.
/// The deprecated `tier2::random_*` string functions are not
/// re-exported here.
///
/// ```
/// let id = mod_rand::unique::unique_hex(16);
/// assert_eq!(id.len(), 16);
/// ```
///
/// The tier 2 string functions warn when used, because they share
/// names with the secure ones:
///
/// ```compile_fail
/// #![deny(deprecated)]
/// let _ = mod_rand::tier2::random_alphanumeric(16);
/// ```
#[cfg(feature = "tier2")]
#[cfg_attr(docsrs, doc(cfg(feature = "tier2")))]
pub mod unique {
    pub use crate::tier2::{
        range_i128, range_i16, range_i32, range_i64, range_i8, range_inclusive_i128,
        range_inclusive_i16, range_inclusive_i32, range_inclusive_i64, range_inclusive_i8,
        range_inclusive_isize, range_inclusive_u128, range_inclusive_u16, range_inclusive_u32,
        range_inclusive_u64, range_inclusive_u8, range_inclusive_usize, range_isize, range_u128,
        range_u16, range_u32, range_u64, range_u8, range_usize, unique_base32, unique_hex,
        unique_name, unique_u64,
    };
}

/// Deterministic seedable PRNG: the same module as [`tier1`].
///
/// Reproducible from its seed, so never a token, a password, or a key.
///
/// ```
/// let mut rng = mod_rand::seeded::Xoshiro256::seed_from_u64(42);
/// let _ = rng.next_u64();
/// ```
pub mod seeded {
    pub use crate::tier1::*;
}
