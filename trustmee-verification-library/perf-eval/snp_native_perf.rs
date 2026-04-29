use anyhow::{ensure, Context, Result};
use clap::Parser;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

mod native_snp;

use native_snp::NativeSnpVerifier;

#[derive(Parser, Debug)]
#[command(name = "snp-native-perf-eval")]
#[command(about = "Measure native SNP verification performance without Wasm runtime")]
struct Args {
    /// Path to the SNP evidence JSON or raw report bytes.
    #[arg(long, default_value = "test_data/snp_evidence.json")]
    evidence: PathBuf,

    /// Cache directory for fetched VCEKs.
    #[arg(long, default_value = ".native-snp-perf-cache")]
    cache_dir: PathBuf,

    /// Number of timed cached end-to-end runs.
    #[arg(long, default_value_t = 20)]
    iterations: usize,

    /// Number of untimed cached end-to-end warmup runs before collecting measurements.
    #[arg(long, default_value_t = 3)]
    warmup: usize,
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn summarize(samples: &[f64]) -> Option<(f64, f64, f64)> {
    let mut iter = samples.iter().copied();
    let first = iter.next()?;
    let mut min = first;
    let mut max = first;
    let mut sum = first;

    for sample in iter {
        min = min.min(sample);
        max = max.max(sample);
        sum += sample;
    }

    Some((sum / samples.len() as f64, min, max))
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.iterations > 0,
        "--iterations must be greater than zero"
    );

    let evidence_bytes =
        fs::read(&args.evidence).with_context(|| format!("read {}", args.evidence.display()))?;
    let prime_start = Instant::now();
    let prime_verifier = NativeSnpVerifier::new()?;
    let prime_result = prime_verifier.verify_bytes(&evidence_bytes, None, None, &args.cache_dir)?;
    let prime_ms = elapsed_ms(prime_start);
    black_box(&prime_result);

    let verify_verifier = NativeSnpVerifier::new()?;

    for _ in 0..args.warmup {
        let result = verify_verifier.verify_bytes(&evidence_bytes, None, None, &args.cache_dir)?;
        black_box(result);
    }

    let mut verify_samples = Vec::with_capacity(args.iterations);
    for _ in 0..args.iterations {
        let start = Instant::now();
        let result = verify_verifier.verify_bytes(&evidence_bytes, None, None, &args.cache_dir)?;
        let sample_ms = elapsed_ms(start);
        verify_samples.push(sample_ms);
        black_box(result);
    }

    let (verify_avg_ms, verify_min_ms, verify_max_ms) =
        summarize(&verify_samples).expect("iterations > 0 guarantees samples are non-empty");

    for _ in 0..args.warmup {
        let verifier = NativeSnpVerifier::new()?;
        let result = verifier.verify_bytes(&evidence_bytes, None, None, &args.cache_dir)?;
        black_box(result);
    }

    let mut samples = Vec::with_capacity(args.iterations);
    let mut last_result = None;
    for _ in 0..args.iterations {
        let start = Instant::now();
        let verifier = NativeSnpVerifier::new()?;
        let result = verifier.verify_bytes(&evidence_bytes, None, None, &args.cache_dir)?;
        let sample_ms = elapsed_ms(start);
        samples.push(sample_ms);
        last_result = Some(result);
    }

    let (avg_ms, min_ms, max_ms) =
        summarize(&samples).expect("iterations > 0 guarantees samples are non-empty");

    println!("mode: snp-native");
    println!("evidence: {}", args.evidence.display());
    println!("iterations: {}", args.iterations);
    println!("warmup: {}", args.warmup);
    println!("prime_end_to_end_ms: {:.3}", prime_ms);
    println!("verify_bytes_avg_ms: {:.3}", verify_avg_ms);
    println!("verify_bytes_min_ms: {:.3}", verify_min_ms);
    println!("verify_bytes_max_ms: {:.3}", verify_max_ms);
    println!("cached_end_to_end_avg_ms: {:.3}", avg_ms);
    println!("cached_end_to_end_min_ms: {:.3}", min_ms);
    println!("cached_end_to_end_max_ms: {:.3}", max_ms);

    if let Some(result) = last_result.as_ref() {
        if let Some(value) = result.get("reported_tcb_snp") {
            println!("reported_tcb_snp: {value}");
        }
        if let Some(value) = result.get("measurement") {
            println!("measurement: {value}");
        }
    }

    println!("note: prime_end_to_end_ms is an untimed cache-priming run before measurements");
    println!(
        "note: verify_bytes_* reuses the same NativeSnpVerifier instance, so it isolates verification after any on-disk cache is already populated"
    );
    println!(
        "note: cached_end_to_end_* creates a fresh NativeSnpVerifier each iteration, so no in-memory verifier state is reused"
    );
    println!(
        "note: if evidence omits cert_chain, on-disk VCEK cache entries under the configured cache directory are reused"
    );

    Ok(())
}
