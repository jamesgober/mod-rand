//! Tiny zero-dependency benchmarking harness.
//!
//! Replaces criterion / libtest #[bench] for this crate. We don't
//! want a `criterion` dev-dependency: the project's whole premise is
//! avoiding the `getrandom`-induced dep ratchet, and dev-deps trip
//! the same ratchet for anyone building from source.

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Run a benchmark target.
///
/// - Warms up for 200ms.
/// - Measures across multiple short batches and takes the median to
///   damp out OS scheduler jitter.
/// - Prints `label   N.NN ns/iter   (over M iters)`.
///
/// The closure should return a value that the caller wants measured;
/// it is passed to `black_box` to prevent the optimiser from deleting
/// the work.
pub fn bench<F, R>(label: &str, mut f: F)
where
    F: FnMut() -> R,
{
    let warmup = Duration::from_millis(200);
    let start = Instant::now();
    while start.elapsed() < warmup {
        black_box(f());
    }

    // Pick batch size so each batch takes ~10ms.
    let probe_iters = 1_000u64;
    let t0 = Instant::now();
    for _ in 0..probe_iters {
        black_box(f());
    }
    let probe_elapsed = t0.elapsed();
    let ns_per_call = probe_elapsed.as_nanos() as f64 / probe_iters as f64;

    let target_batch_ns = 10_000_000.0;
    let batch_size = ((target_batch_ns / ns_per_call.max(1.0)) as u64).max(1_000);

    // 9 batches; report the median.
    let mut times = Vec::with_capacity(9);
    for _ in 0..9 {
        let t = Instant::now();
        for _ in 0..batch_size {
            black_box(f());
        }
        times.push(t.elapsed().as_nanos() as f64 / batch_size as f64);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = times[times.len() / 2];

    println!("{label:<28} {median:>9.2} ns/iter   ({batch_size} iters x 9 batches)");
}
