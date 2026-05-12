# mod-rand — API Reference

> Hand-written companion to the rustdoc on [docs.rs/mod-rand](https://docs.rs/mod-rand).
> The rustdoc is authoritative for signatures; this document explains the
> *why* behind each tier and gives guidance on when to pick which.

## Crate layout

```text
mod_rand
├── tier1   — fast deterministic PRNG (xoshiro256**)        [always]
├── tier2   — process-unique seeds                          [feature: tier2]
└── tier3   — OS-backed cryptographic random                [feature: tier3]
```

## Picking a tier

| Question                                           | Tier |
|----------------------------------------------------|------|
| Is the value reproducible from a seed?             | 1    |
| Must two calls inside one process always differ?   | 2    |
| Could an attacker benefit from predicting it?      | 3    |

If the answer to the third question is "yes" — even maybe — use Tier 3.
Tier 1 and Tier 2 are **not** safe substitutes.

---

## Tier 1 — `mod_rand::tier1`

Deterministic PRNG built on **xoshiro256\*\*** (Blackman & Vigna). 256
bits of state, period of `2^256 − 1`, passes the BigCrush test battery.
Single-seed expansion uses **splitmix64**, the seeding strategy
recommended by the algorithm authors.

### Availability

- Always compiled in. No feature flag required.
- Works in `no_std`.

### API

```rust
pub struct Xoshiro256 { /* private */ }

impl Xoshiro256 {
    pub fn seed_from_u64(seed: u64) -> Self;
    pub fn from_state(state: [u64; 4]) -> Option<Self>;
    pub fn state(&self) -> [u64; 4];

    pub fn next_u64(&mut self) -> u64;
    pub fn next_u32(&mut self) -> u32;
    pub fn next_f64(&mut self) -> f64;

    pub fn fill_bytes(&mut self, buf: &mut [u8]);

    pub fn jump(&mut self);       // advances by 2^128 calls
    pub fn long_jump(&mut self);  // advances by 2^192 calls
}
```

### Guarantees

- **Reproducibility.** Same seed ⇒ same output stream forever.
- **Period.** `2^256 − 1` — large enough that no single program will
  exhaust it.
- **Statistical quality.** Passes BigCrush (per the original
  xoshiro256\*\* paper) and the chi-squared / runs tests bundled in
  `tests/statistical.rs` of this crate.
- **`from_state` rejection.** The all-zero state is the single fixed
  point of the xoshiro transition; `from_state([0; 4])` returns
  `None` rather than producing a degenerate stream.

### Non-guarantees

- **Not cryptographic.** An adversary who observes ~2 KiB of output
  can recover the internal state in linear time and predict every
  subsequent draw. Use Tier 3 for tokens.

### Parallel streams

To split into independent streams that won't collide:

```rust
use mod_rand::tier1::Xoshiro256;

let mut master = Xoshiro256::seed_from_u64(42);
let mut worker_a = master.clone();
let mut worker_b = master.clone();
worker_b.jump();          // worker_b is now 2^128 calls ahead of worker_a
let mut worker_c = master.clone();
worker_c.long_jump();     // worker_c is 2^192 calls ahead
```

`jump()` partitions the period into `2^128` non-overlapping streams of
`2^128` outputs each. `long_jump()` partitions into `2^64` of `2^192`.

### Performance

Measured with `cargo bench --bench tier1` on x86_64:

| op                 | time     |
|--------------------|----------|
| `next_u64`         | ~0.6 ns  |
| `next_u32`         | ~0.7 ns  |
| `next_f64`         | ~0.7 ns  |
| `fill_bytes(32)`   | ~2 ns    |
| `fill_bytes(4096)` | ~250 ns  |
| `seed_from_u64`    | ~0.4 ns  |

---

## Tier 2 — `mod_rand::tier2`

Process-unique values from PID + nanosecond timestamp + atomic
counter, mixed with a strong 64-bit avalanche function (Stafford
variant 13).

### Availability

- `feature = "tier2"` (default-on). Requires `std`.

### API

```rust
pub fn unique_u64() -> u64;
pub fn unique_name(len: usize)   -> String;  // Crockford base32
pub fn unique_base32(len: usize) -> String;  // synonym for unique_name
pub fn unique_hex(len: usize)    -> String;  // lowercase hex
```

All string variants return *exactly* `len` characters. `len = 0`
returns the empty string and makes no allocation.

### Guarantees

- **Distinct within a process.** Two calls to `unique_u64()` from the
  same process never return the same value (counter monotonically
  increments; values mix it in such that it cannot be cancelled).
- **Likely-distinct across processes.** PID + nanos make collisions
  vanishingly unlikely between independent processes on the same
  host.
- **Filesystem-safe strings.** Crockford base32 omits `I`, `L`, `O`,
  `U` to avoid visual ambiguity, and contains no characters that
  require shell-escaping.

### Non-guarantees

- **Not cryptographic.** Output is uniform-looking but recoverable
  given enough observations.
- **Not cross-host unique.** Two different machines may produce the
  same value (PID + nanos can collide). Use Tier 3 if cross-host
  uniqueness matters.

### Performance

Measured with `cargo bench --bench tier2`:

| op                  | time     |
|---------------------|----------|
| `unique_u64`        | ~20 ns   |
| `unique_name(8)`    | ~40 ns   |
| `unique_name(16)`   | ~65 ns   |
| `unique_hex(16)`    | ~45 ns   |
| `unique_base32(16)` | ~65 ns   |

Cost is dominated by `SystemTime::now()`; the mixing function is
single-digit ns.

---

## Tier 3 — `mod_rand::tier3`

Cryptographically secure random pulled directly from the OS's secure
random source.

### Availability

- `feature = "tier3"` (default-on). Requires `std`.

### API

```rust
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()>;
pub fn random_u32()               -> io::Result<u32>;
pub fn random_u64()               -> io::Result<u64>;
pub fn random_bytes(len: usize)   -> io::Result<Vec<u8>>;
pub fn random_hex(bytes: usize)   -> io::Result<String>;
pub fn random_base32(chars: usize) -> io::Result<String>;
```

### Source per platform

| Platform     | Source                                  |
|--------------|-----------------------------------------|
| Linux        | `getrandom(2)` syscall                  |
| macOS        | `getentropy(3)` from libSystem          |
| Windows      | `BCryptGenRandom` from `bcrypt.dll`     |
| Other Unix   | `/dev/urandom`                          |
| Other        | `io::ErrorKind::Unsupported`            |

On Linux, if `getrandom` returns `ENOSYS` (kernel older than 3.17 —
older than every supported Rust target), the implementation falls
back to `/dev/urandom`. **This is not a security downgrade** —
`/dev/urandom` is a fully-supported cryptographic source on every
listed platform; it is, in fact, the source `getrandom` ultimately
draws from. The fallback is *only* taken on `ENOSYS` (the syscall
does not exist), never on a *failed* syscall.

### Guarantees

- **Cryptographic.** Output is unpredictable to an adversary, even
  one who has observed prior outputs.
- **No silent fallback to a weaker source.** On syscall failure, the
  return is `io::Error` — never a value drawn from a non-cryptographic
  source.
- **Fork / snapshot / VM-resume safe.** No internal userspace state
  to clone; every call reaches the kernel.
- **EINTR-tolerant.** On Linux and macOS, signal interruptions are
  retried transparently.

### Error semantics

The returned `io::Error` preserves the OS error code via
`io::Error::from_raw_os_error`. On Windows, the NTSTATUS is embedded
in the error message. Common cases:

- **Sandboxed process (Linux seccomp filter)** — error.
- **macOS sandbox blocking entropy** — error.
- **Kernel entropy pool not yet seeded (very early boot)** — the
  syscall *blocks* rather than failing. This is the desired
  behaviour — predictable boot-time random is the classic real-world
  weakness this tier prevents.

### Performance

Measured with `cargo bench --bench tier3` on Windows:

| op                  | time      |
|---------------------|-----------|
| `random_u32`        | ~32 ns    |
| `random_u64`        | ~35 ns    |
| `fill_bytes(16)`    | ~40 ns    |
| `fill_bytes(32)`    | ~55 ns    |
| `fill_bytes(1024)`  | ~220 ns   |
| `random_hex(16)`    | ~100 ns   |
| `random_base32(16)` | ~90 ns    |

Linux and macOS numbers are kernel-dependent; expect 100–500 ns per
call on commodity hardware.

---

## Feature flags

```toml
[dependencies]
mod-rand = { version = "0.9", default-features = false }   # tier1 only, no_std
mod-rand = { version = "0.9", features = ["tier2"] }       # + tier2
mod-rand = "0.9"                                             # all three tiers (default)
```

| Feature  | Pulls in   | Effect                          |
|----------|------------|---------------------------------|
| `std`    | std        | required for tier2, tier3       |
| `tier2`  | std        | enables `mod_rand::tier2`       |
| `tier3`  | std        | enables `mod_rand::tier3`       |

Default features: `["std", "tier2", "tier3"]`.

## MSRV

`1.75`. Pinned in `Cargo.toml`. CI verifies on this exact toolchain
on every change.

## Dependencies

Zero runtime crate dependencies. Platform syscalls are declared
inline via `extern "C"` blocks; no `libc`, no `getrandom` crate, no
`rand` crate.

## Stability

Through `0.9.x`, the API may shift in minor ways. The `1.0` release
will pin the public API and the per-tier guarantees described above.

## See also

- [REPS.md](../REPS.md) — formal project specification.
- [CHANGELOG.md](../CHANGELOG.md) — release history.
- [examples/](../examples/) — runnable per-tier examples.
- [benches/](../benches/) — microbenchmarks (no external deps).
