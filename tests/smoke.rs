use mod_rand::tier1::Xoshiro256;

#[test]
fn smoke_tier1_seed_works() {
    let mut rng = Xoshiro256::seed_from_u64(1);
    let _ = rng.next_u64();
}

#[test]
fn smoke_tier1_reproducible() {
    let mut a = Xoshiro256::seed_from_u64(42);
    let mut b = Xoshiro256::seed_from_u64(42);
    for _ in 0..32 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[cfg(feature = "tier2")]
#[test]
fn smoke_tier2_unique() {
    use mod_rand::tier2;
    let a = tier2::unique_u64();
    let b = tier2::unique_u64();
    assert_ne!(a, b);
}

#[cfg(feature = "tier2")]
#[test]
fn smoke_tier2_name() {
    use mod_rand::tier2;
    let n = tier2::unique_name(16);
    assert!(n.len() >= 16);
}

#[cfg(feature = "tier3")]
#[test]
fn smoke_tier3_fill() {
    use mod_rand::tier3;
    let mut buf = [0u8; 32];
    tier3::fill_bytes(&mut buf).unwrap();
}

#[cfg(feature = "tier3")]
#[test]
fn smoke_tier3_hex_length() {
    use mod_rand::tier3;
    let h = tier3::random_hex(16).unwrap();
    assert_eq!(h.len(), 32);
}
