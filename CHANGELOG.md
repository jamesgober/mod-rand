# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

This is the name-claim release. The real implementations land in
`0.9.x`:

- Full xoshiro256\*\* algorithm with splitmix64 seeding.
- Production-quality mixing function for tier2.
- Real platform syscalls (`getrandom(2)` on Linux,
  `BCryptGenRandom` on Windows, `getentropy(3)` on macOS) for tier3.

**Do not use tier3 for security-sensitive work in `v0.1.0`.** The
placeholder is not cryptographically secure.

[Unreleased]: https://github.com/jamesgober/mod-rand/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesgober/mod-rand/releases/tag/v0.1.0
