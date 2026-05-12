//! Statistical helpers shared by the integration test suite.

/// Compute the chi-squared statistic for a byte buffer against the
/// uniform distribution over 256 buckets.
///
/// Returns the raw chi-squared value (sum of `(observed-expected)^2 /
/// expected` over all 256 buckets). For 255 degrees of freedom the
/// upper-tail critical value at α = 0.001 is approximately 330.
pub fn byte_frequency_chi_squared(buf: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in buf {
        counts[b as usize] += 1;
    }
    let n = buf.len() as f64;
    let expected = n / 256.0;
    counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

/// Approximate Wald–Wolfowitz runs statistic on a byte buffer,
/// categorising each byte as 0 or 1 by comparison with the median
/// value 0x80.
///
/// Returns the standardised z-score. |z| > 6 implies a stream far
/// from chance — typically a stuck or biased source.
pub fn runs_test_statistic(buf: &[u8]) -> f64 {
    // Binarise: 1 if byte >= 0x80, else 0.
    let n = buf.len();
    if n < 2 {
        return 0.0;
    }
    let mut n1 = 0u64;
    let mut n0 = 0u64;
    let mut runs = 1u64;
    let mut prev = buf[0] >= 0x80;
    if prev {
        n1 += 1;
    } else {
        n0 += 1;
    }
    for &b in &buf[1..] {
        let cur = b >= 0x80;
        if cur != prev {
            runs += 1;
            prev = cur;
        }
        if cur {
            n1 += 1;
        } else {
            n0 += 1;
        }
    }
    let n_total = (n1 + n0) as f64;
    let mu = 2.0 * (n1 as f64) * (n0 as f64) / n_total + 1.0;
    let var = (mu - 1.0) * (mu - 2.0) / (n_total - 1.0);
    if var <= 0.0 {
        return 0.0;
    }
    (runs as f64 - mu) / var.sqrt()
}
