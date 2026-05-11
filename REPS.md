# mod-rand — Project Specification (REPS)

> Rust Engineering Project Specification.
> Normative language follows RFC 2119.

## 1. Purpose

`mod-rand` MUST provide random number generation at three quality
tiers in a single zero-dependency library. Users pick the tier
appropriate to their threat model.

## 2. The three tiers

### Tier 1: Fast deterministic PRNG

MUST be:
- Seedable from a single `u64`
- Reproducible (same seed produces same stream)
- Fast (target: ~1ns per `u64` on commodity hardware)
- Available in `no_std`
- Algorithm: xoshiro256\*\* with splitmix64 seeding

MUST NOT be:
- Used for security-sensitive randomness
- Marketed as cryptographically secure

### Tier 2: Process-unique seeds

MUST be:
- Different across calls within a process (counter-guaranteed)
- Different across processes with extremely high probability
- Fast (target: <100ns per call)
- Available when `std` feature is enabled
- Algorithm: PID + nanosecond timestamp + atomic counter, mixed
  with a fast mixing function (xorshift rounds or similar)

MUST NOT be:
- Used for security-sensitive randomness
- Used where two simultaneous calls returning the same value would
  cause correctness bugs (the counter prevents this, but only within
  a single process)

### Tier 3: OS-backed cryptographic random

MUST be:
- Backed by the OS's secure random source:
  - Linux: `getrandom(2)` syscall
  - macOS: `getentropy(3)`
  - Windows: `BCryptGenRandom`
- Cryptographically secure (output unpredictable by an attacker)
- Available when `std` feature is enabled
- Resilient to fork/snapshot/VM-resume (no internal state to mix)

MUST NOT be:
- Optimized for speed at the cost of security
- Allowed to silently fall back to a weaker source on syscall failure
  (must return an error instead)

## 3. API surface

### Tier 1

```rust
pub struct Xoshiro256 { /* private */ }

impl Xoshiro256 {
    pub fn seed_from_u64(seed: u64) -> Self;
    pub fn next_u64(&mut self) -> u64;
}
```

### Tier 2

```rust
pub fn unique_u64() -> u64;
pub fn unique_name(len: usize) -> String;
```

### Tier 3

```rust
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()>;
pub fn random_u64() -> io::Result<u64>;
pub fn random_hex(bytes: usize) -> io::Result<String>;
```

Additional convenience constructors (bounded integers, range
selection, etc.) MAY land in `0.9.x` or later.

## 4. Determinism

- Tier 1 output MUST be deterministic given a seed.
- Tier 2 output MUST be unique across calls within a process.
- Tier 3 output MUST be non-deterministic.

## 5. Dependencies

This crate MUST NOT have runtime dependencies outside of `std` (when
the `std` feature is enabled). Platform-specific FFI declarations
SHOULD be inlined rather than pulled in via `libc`.

The point: this crate exists partly to break the `getrandom`-induced
MSRV ratchet. We can't replace one MSRV-locking dep with another.

## 6. Stability

Through `0.9.x` the public API MAY shift. The `1.0` release pins the
API and the tier definitions.

## 7. Out of scope

- Generic distribution types (Normal, Poisson, etc.) — that's
  `rand_distr` territory.
- Trait-heavy abstraction (`Rng` / `RngCore` / `SeedableRng`) — we
  expose concrete types.
- Hardware random sources (RDRAND, RDSEED) — out of scope for
  initial release; may revisit if there's demand.
- Multi-thread coordination (shared atomic-state RNGs) — Tier 2's
  atomic counter is enough; if users want shared Tier 1, they wrap
  one themselves.
