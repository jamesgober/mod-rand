//! Concurrency tests for Tier 2 and Tier 3.
//!
//! Tier 2's correctness story rests on its atomic counter: 1 000 000
//! calls produce 1 000 000 distinct values within a process. The
//! single-thread test in `tests/statistical.rs` verifies that under
//! ideal conditions. Here we verify it survives high-contention
//! multi-threaded access — the case where a broken counter would
//! actually visibly collide.
//!
//! Tier 3 is documented as thread-safe (every call is independent —
//! no shared mutable state). We exercise it under contention as a
//! smoke test for that claim.

#[cfg(feature = "tier2")]
#[test]
fn tier2_unique_u64_distinct_under_thread_contention() {
    use mod_rand::tier2;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let thread_count = 8;
    let per_thread = 50_000;
    let shared: Arc<Mutex<HashSet<u64>>> = Arc::new(Mutex::new(HashSet::with_capacity(
        thread_count * per_thread,
    )));

    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let mut local: Vec<u64> = Vec::with_capacity(per_thread);
            for _ in 0..per_thread {
                local.push(tier2::unique_u64());
            }
            let mut set = shared.lock().unwrap();
            for v in local {
                // Within-process uniqueness invariant.
                assert!(
                    set.insert(v),
                    "tier2::unique_u64 collision under contention: {v:#x}"
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let set = shared.lock().unwrap();
    assert_eq!(set.len(), thread_count * per_thread);
}

#[cfg(feature = "tier2")]
#[test]
fn tier2_unique_names_distinct_under_thread_contention() {
    use mod_rand::tier2;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let thread_count = 8;
    let per_thread = 20_000;
    let shared: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::with_capacity(
        thread_count * per_thread,
    )));

    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let mut local: Vec<String> = Vec::with_capacity(per_thread);
            for _ in 0..per_thread {
                local.push(tier2::unique_name(20));
            }
            let mut set = shared.lock().unwrap();
            for v in local {
                assert!(
                    set.insert(v),
                    "tier2::unique_name collision under contention"
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(feature = "tier3")]
#[test]
fn tier3_concurrent_calls_succeed() {
    use mod_rand::tier3;
    use std::thread;

    let thread_count = 8;
    let per_thread = 1_000;

    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let mut buf = [0u8; 32];
                tier3::fill_bytes(&mut buf).expect("tier3 must not fail under contention");
                // The probability that even two threads draw identical
                // 32-byte buffers is 2^-256 — observing it is a bug.
                // We don't bother asserting; just exercise the syscall
                // path under load.
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(feature = "tier3")]
#[test]
fn tier3_concurrent_tokens_distinct() {
    use mod_rand::tier3;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let thread_count = 4;
    let per_thread = 5_000;
    let shared: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::with_capacity(
        thread_count * per_thread,
    )));

    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let mut local: Vec<String> = Vec::with_capacity(per_thread);
            for _ in 0..per_thread {
                local.push(tier3::random_hex(16).unwrap());
            }
            let mut set = shared.lock().unwrap();
            for tok in local {
                // 128-bit tokens collide at chance rate 2^-128; observing
                // a collision means the CSPRNG is broken or shared state
                // is leaking.
                assert!(set.insert(tok), "tier3 token collision");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
