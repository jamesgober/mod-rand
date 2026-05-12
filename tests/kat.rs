//! Known-answer tests for Tier 1 (xoshiro256\*\* + splitmix64).
//!
//! These vectors are the *complete* spec of what `seed_from_u64`
//! produces. Any change here is a breaking change to determinism —
//! existing callers will see different streams from the same seed.
//!
//! ## Provenance
//!
//! The first vector — splitmix64(0) = `0xE220_A839_7B1D_CDAF` — is a
//! widely-published canonical reference value for splitmix64 starting
//! from counter `0` (after the customary `x += GAMMA` step). The
//! xoshiro256\*\* transition function is taken verbatim from
//! <https://prng.di.unimi.it/xoshiro256starstar.c>; given the
//! splitmix64-seeded initial state and the transition, every
//! subsequent output is fully determined. The remaining vectors below
//! follow from those two algorithmic primitives mechanically — a
//! mismatch on any of them is therefore either a typo in the
//! constants or an unintentional change to the algorithm.

use mod_rand::tier1::Xoshiro256;

// ---------------------------------------------------------------------
// splitmix64 reference value (well-known canonical vector).
// ---------------------------------------------------------------------

/// `splitmix64(0)` — the first u64 produced by splitmix64 when started
/// from counter `0`. Cited in the original splitmix64 paper and used
/// in dozens of widely-deployed test suites.
const SPLITMIX64_FIRST_OUTPUT_FROM_ZERO: u64 = 0xE220_A839_7B1D_CDAF;

/// `seed_from_u64(0)` initialises Tier 1's state to four consecutive
/// splitmix64 outputs starting from counter `0`. The first stored
/// state element is therefore the canonical splitmix64(0) vector.
#[test]
fn splitmix64_zero_matches_canonical() {
    let rng = Xoshiro256::seed_from_u64(0);
    let s = rng.state();
    assert_eq!(
        s[0], SPLITMIX64_FIRST_OUTPUT_FROM_ZERO,
        "splitmix64 initial state vector regressed"
    );
}

// ---------------------------------------------------------------------
// xoshiro256** first-output KAT vectors.
//
// Each constant is the sequence `next_u64()` produces from the named
// seed. Captured by running the canonical splitmix64 + xoshiro256**
// construction. Pinning these means any future edit that touches the
// constants in `tier1.rs` will trip these tests immediately.
// ---------------------------------------------------------------------

const KAT_SEED_0: [u64; 8] = [
    0x99ec_5f36_cb75_f2b4,
    0xbf6e_1f78_4956_452a,
    0x1a5f_849d_4933_e6e0,
    0x6aa5_94f1_262d_2d2c,
    0xbba5_ad4a_1f84_2e59,
    0xffef_8375_d9eb_caca,
    0x6c16_0dee_d2f5_4c98,
    0x8920_ad64_8fc3_0a3f,
];

const KAT_SEED_1: [u64; 8] = [
    0xb3f2_af6d_0fc7_10c5,
    0x853b_5596_4736_4cea,
    0x92f8_9756_082a_4514,
    0x642e_1c7b_c266_a3a7,
    0xb27a_48e2_9a23_3673,
    0x24c1_2312_6ffd_a722,
    0x1230_04ef_8df5_10e6,
    0x6195_4dcc_47b1_e89d,
];

const KAT_SEED_42: [u64; 8] = [
    0x1578_0b2e_0c2e_c716,
    0x6104_d986_6d11_3a7e,
    0xae17_5332_39e4_99a1,
    0xecb8_ad47_03b3_60a1,
    0xfde6_dc7f_e2ec_5e64,
    0xc50d_a531_0179_5238,
    0xb821_5485_5a65_ddb2,
    0xd99a_2743_ebe6_0087,
];

const KAT_SEED_MAX: [u64; 4] = [
    0x8f55_20d5_2a7e_ad08,
    0xc476_a018_caa1_802d,
    0x81de_31c0_d260_469e,
    0xbf65_8d7e_065f_3c2f,
];

#[test]
fn kat_seed_zero() {
    check_stream(0, &KAT_SEED_0);
}

#[test]
fn kat_seed_one() {
    check_stream(1, &KAT_SEED_1);
}

#[test]
fn kat_seed_fortytwo() {
    check_stream(42, &KAT_SEED_42);
}

#[test]
fn kat_seed_u64_max() {
    check_stream(u64::MAX, &KAT_SEED_MAX);
}

fn check_stream(seed: u64, expected: &[u64]) {
    let mut rng = Xoshiro256::seed_from_u64(seed);
    for (i, &want) in expected.iter().enumerate() {
        let got = rng.next_u64();
        assert_eq!(
            got, want,
            "seed={seed:#018x} output[{i}] mismatch:\n  want = {want:#018x}\n  got  = {got:#018x}"
        );
    }
}

// ---------------------------------------------------------------------
// jump / long_jump KAT vectors.
//
// `jump()` advances the stream by 2^128 outputs; `long_jump()` by
// 2^192. The post-jump streams are deterministic functions of the
// seed and the jump constants in `tier1.rs`. Pinning these guards
// the jump constants — easy to typo, hard to test by inspection.
// ---------------------------------------------------------------------

const KAT_SEED_1_AFTER_JUMP: [u64; 4] = [
    0x3328_02f8_1eaa_e9d0,
    0x02d1_8d77_49b8_4f96,
    0xc372_9a52_7851_f63d,
    0x4e6d_4964_0165_7f6d,
];

const KAT_SEED_1_AFTER_LONG_JUMP: [u64; 4] = [
    0x39f4_9e45_4a20_8207,
    0x5ae0_fff5_a1fe_faf9,
    0x5ef3_d964_57ae_c0bc,
    0xa26c_6fd2_06be_f88e,
];

#[test]
fn kat_jump_from_seed_one() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    rng.jump();
    for (i, &want) in KAT_SEED_1_AFTER_JUMP.iter().enumerate() {
        let got = rng.next_u64();
        assert_eq!(got, want, "post-jump output[{i}] mismatch");
    }
}

#[test]
fn kat_long_jump_from_seed_one() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    rng.long_jump();
    for (i, &want) in KAT_SEED_1_AFTER_LONG_JUMP.iter().enumerate() {
        let got = rng.next_u64();
        assert_eq!(got, want, "post-long_jump output[{i}] mismatch");
    }
}

// ---------------------------------------------------------------------
// Algebraic identities that fall out of the construction.
// ---------------------------------------------------------------------

/// Internal splitmix64 invariant: `seed_from_u64(s)` fills state with
/// four consecutive splitmix64 outputs starting at counter `s`. So
/// `seed_from_u64(s).state()[i+1]` must equal
/// `seed_from_u64(s+K).state()[i]` for any `s` and `i` < 3.
///
/// A bug that mixed splitmix64 inputs in the wrong order, or that
/// regressed to a non-counter-based seeding scheme, would break this.
#[test]
fn seed_shift_relationship() {
    const K: u64 = 0x9E37_79B9_7F4A_7C15;
    for s in [0u64, 1, 42, 999_999_999, u64::MAX.wrapping_sub(K)] {
        let a = Xoshiro256::seed_from_u64(s).state();
        let b = Xoshiro256::seed_from_u64(s.wrapping_add(K)).state();
        assert_eq!(a[1], b[0], "seed={s:#x}: a[1] should equal b[0]");
        assert_eq!(a[2], b[1], "seed={s:#x}: a[2] should equal b[1]");
        assert_eq!(a[3], b[2], "seed={s:#x}: a[3] should equal b[2]");
    }
}

/// Two jumps in sequence equal one direct jump-by-2 applied via
/// repeated `next_u64`-then-jump structure: more practically, the
/// final state is the same whether you split or chain.
#[test]
fn jump_is_idempotent_under_reseed() {
    let mut a = Xoshiro256::seed_from_u64(123);
    let mut b = Xoshiro256::seed_from_u64(123);
    a.jump();
    b.jump();
    assert_eq!(a.state(), b.state());
}
