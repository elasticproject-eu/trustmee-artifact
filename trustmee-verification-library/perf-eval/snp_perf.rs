use anyhow::{ensure, Context, Result};
use clap::Parser;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

#[derive(Parser, Debug)]
#[command(name = "snp-perf-eval")]
#[command(about = "Measure SNP verification performance with wasm-verification-component")]
struct Args {
    /// Path to the SNP verifier component (.wasm).
    #[arg(long, default_value = "test_data/snp_verifier_component.wasm")]
    component: PathBuf,

    /// Path to the SNP evidence JSON.
    #[arg(long, default_value = "test_data/snp_evidence.json")]
    evidence: PathBuf,

    /// Cache directory pre-opened to the component as `cache/`.
    #[arg(long, default_value = ".wasm-verification-component-snp-perf-cache")]
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

    let component_bytes =
        fs::read(&args.component).with_context(|| format!("read {}", args.component.display()))?;
    let evidence_bytes =
        fs::read(&args.evidence).with_context(|| format!("read {}", args.evidence.display()))?;

    let options = VerifyOptions {
        cache_dir: args.cache_dir.clone(),
        pccs_url: None,
        component_repository_hint: None,
        component_trust_store: None,
    };

    let prime_start = Instant::now();
    let prime_verifier = WasmVerificationComponent::new()?;
    let prime_result =
        prime_verifier.verify_bytes(&component_bytes, &evidence_bytes, None, None, &options)?;
    let prime_ms = elapsed_ms(prime_start);
    black_box(&prime_result);

    for _ in 0..args.warmup {
        let verifier = WasmVerificationComponent::new()?;
        let component = verifier.load_component(&component_bytes)?;
        black_box(component);
    }

    let mut load_samples = Vec::with_capacity(args.iterations);
    for _ in 0..args.iterations {
        let verifier = WasmVerificationComponent::new()?;
        let start = Instant::now();
        let component = verifier.load_component(&component_bytes)?;
        let sample_ms = elapsed_ms(start);
        load_samples.push(sample_ms);
        black_box(component);
    }

    let (load_avg_ms, load_min_ms, load_max_ms) =
        summarize(&load_samples).expect("iterations > 0 guarantees samples are non-empty");

    let verify_verifier = WasmVerificationComponent::new()?;
    let verify_component = verify_verifier.load_component(&component_bytes)?;

    for _ in 0..args.warmup {
        let result = verify_verifier.verify_loaded_component(
            &verify_component,
            &evidence_bytes,
            None,
            None,
            &options,
        )?;
        black_box(result);
    }

    let mut verify_samples = Vec::with_capacity(args.iterations);
    for _ in 0..args.iterations {
        let start = Instant::now();
        let result = verify_verifier.verify_loaded_component(
            &verify_component,
            &evidence_bytes,
            None,
            None,
            &options,
        )?;
        let sample_ms = elapsed_ms(start);
        verify_samples.push(sample_ms);
        black_box(result);
    }

    let (verify_avg_ms, verify_min_ms, verify_max_ms) =
        summarize(&verify_samples).expect("iterations > 0 guarantees samples are non-empty");

    let memory_cached_verifier = WasmVerificationComponent::new()?;
    let memory_cached_component = memory_cached_verifier.load_component(&component_bytes)?;
    black_box(&memory_cached_component);

    for _ in 0..args.warmup {
        let component = memory_cached_verifier.load_component(&component_bytes)?;
        let result = memory_cached_verifier.verify_loaded_component(
            &component,
            &evidence_bytes,
            None,
            None,
            &options,
        )?;
        black_box(result);
    }

    let mut memory_cached_samples = Vec::with_capacity(args.iterations);
    for _ in 0..args.iterations {
        let start = Instant::now();
        let component = memory_cached_verifier.load_component(&component_bytes)?;
        let result = memory_cached_verifier.verify_loaded_component(
            &component,
            &evidence_bytes,
            None,
            None,
            &options,
        )?;
        let sample_ms = elapsed_ms(start);
        memory_cached_samples.push(sample_ms);
        black_box(result);
    }

    let (memory_cached_avg_ms, memory_cached_min_ms, memory_cached_max_ms) =
        summarize(&memory_cached_samples).expect("iterations > 0 guarantees samples are non-empty");

    for _ in 0..args.warmup {
        let verifier = WasmVerificationComponent::new()?;
        let component = verifier.load_component(&component_bytes)?;
        let result =
            verifier.verify_loaded_component(&component, &evidence_bytes, None, None, &options)?;
        black_box(result);
    }

    let mut samples = Vec::with_capacity(args.iterations);
    let mut last_result = None;
    for _ in 0..args.iterations {
        let start = Instant::now();
        let verifier = WasmVerificationComponent::new()?;
        let component = verifier.load_component(&component_bytes)?;
        let result =
            verifier.verify_loaded_component(&component, &evidence_bytes, None, None, &options)?;
        let sample_ms = elapsed_ms(start);
        samples.push(sample_ms);
        last_result = Some(result);
    }

    let (avg_ms, min_ms, max_ms) =
        summarize(&samples).expect("iterations > 0 guarantees samples are non-empty");

    println!("mode: snp");
    println!("component: {}", args.component.display());
    println!("evidence: {}", args.evidence.display());
    println!("iterations: {}", args.iterations);
    println!("warmup: {}", args.warmup);
    println!("prime_end_to_end_ms: {:.3}", prime_ms);
    println!("load_component_avg_ms: {:.3}", load_avg_ms);
    println!("load_component_min_ms: {:.3}", load_min_ms);
    println!("load_component_max_ms: {:.3}", load_max_ms);
    println!("verify_loaded_component_avg_ms: {:.3}", verify_avg_ms);
    println!("verify_loaded_component_min_ms: {:.3}", verify_min_ms);
    println!("verify_loaded_component_max_ms: {:.3}", verify_max_ms);
    println!(
        "memory_cached_end_to_end_avg_ms: {:.3}",
        memory_cached_avg_ms
    );
    println!(
        "memory_cached_end_to_end_min_ms: {:.3}",
        memory_cached_min_ms
    );
    println!(
        "memory_cached_end_to_end_max_ms: {:.3}",
        memory_cached_max_ms
    );
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
        "note: load_component_* uses a fresh WasmVerificationComponent each iteration, so it measures cached load without reusing the in-memory loaded component"
    );
    println!(
        "note: verify_loaded_component_* reuses the same WasmVerificationComponent and loaded component, so it isolates verification after the component is already in memory"
    );
    println!(
        "note: memory_cached_end_to_end_* reuses the same WasmVerificationComponent and calls load_component() each iteration, so the loaded component cache is served from memory"
    );
    println!(
        "note: cached_end_to_end_* creates a fresh WasmVerificationComponent each iteration, so the component is not reused from in-memory caches"
    );
    println!("note: the Wasmtime compile cache on disk is still reused when present");

    Ok(())
}
