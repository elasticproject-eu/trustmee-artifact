//! Paper-eval helper that times `wasmtime::component::Component::from_binary`
//! on the verifier wasm components.
//!
//! For each component the helper measures two regimes:
//!   * `no_cache`        — engine built without a disk cache; every run does
//!                         a full Cranelift compile.
//!   * `with_disk_cache` — engine built with a fresh on-disk compilation
//!                         cache. The first run pays the compile and writes
//!                         to the cache; subsequent runs deserialise from
//!                         disk.
//!
//! Output: a single JSON file at `--output`, plus a brief summary on stdout.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use wasmtime::component::Component;
use wasmtime::{Cache, Config, Engine};

#[derive(Parser, Debug)]
#[command(name = "wasmtime-compile-bench")]
#[command(about = "Time wasmtime Component::from_binary for verifier wasm components")]
struct Args {
    /// One or more `LABEL=PATH` mappings naming the wasm components to bench.
    /// Example: `--component snp_verifier=/path/to/snp_verifier_component.wasm`
    #[arg(long = "component", required = true, value_name = "LABEL=PATH")]
    components: Vec<String>,

    /// How many runs per regime per component.
    #[arg(long, default_value_t = 5)]
    runs: usize,

    /// Scratch directory for the wasmtime disk cache + cache config files.
    #[arg(long, default_value = "/tmp/wasmtime-compile-bench")]
    bench_dir: PathBuf,

    /// Where to write the JSON summary.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct Stats {
    runs: usize,
    samples_ms: Vec<f64>,
    mean_ms: f64,
    std_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

#[derive(Serialize)]
struct WithDiskCache {
    first_run_ms: f64,
    warm: Stats,
}

#[derive(Serialize)]
struct ComponentEntry {
    wasm_path: String,
    wasm_bytes: u64,
    no_cache: Stats,
    with_disk_cache: WithDiskCache,
}

#[derive(Serialize)]
struct Output {
    wasmtime_version: String,
    runs_per_regime: usize,
    components: serde_json::Map<String, serde_json::Value>,
}

fn stats_from_samples(samples: &[f64]) -> Stats {
    let runs = samples.len();
    let mean = samples.iter().sum::<f64>() / runs.max(1) as f64;
    let var = samples
        .iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f64>()
        / runs.max(1) as f64;
    let std = var.sqrt();
    let min = samples.iter().copied().fold(f64::INFINITY, f64::min);
    let max = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    Stats {
        runs,
        samples_ms: samples.to_vec(),
        mean_ms: mean,
        std_ms: std,
        min_ms: if min.is_finite() { min } else { 0.0 },
        max_ms: if max.is_finite() { max } else { 0.0 },
    }
}

fn measure_no_cache(wasm_bytes: &[u8], runs: usize) -> Result<Stats> {
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config).context("create wasmtime engine (no cache)")?;
        let start = Instant::now();
        let _component = Component::from_binary(&engine, wasm_bytes)
            .context("compile component (no cache)")?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(stats_from_samples(&samples))
}

fn measure_with_disk_cache(
    wasm_bytes: &[u8],
    runs: usize,
    cache_dir: &Path,
    cache_config_path: &Path,
) -> Result<WithDiskCache> {
    // Reset cache dir (so the first run is a true cold-cache compile) and
    // re-write the cache config — keep the config file *outside* the cache
    // dir so wasmtime's cleanup can't remove it.
    let _ = std::fs::remove_dir_all(cache_dir);
    std::fs::create_dir_all(cache_dir).context("create disk cache dir")?;
    if let Some(parent) = cache_config_path.parent() {
        std::fs::create_dir_all(parent).context("create cache config parent")?;
    }
    let toml = format!("[cache]\ndirectory = {:?}\n", cache_dir);
    std::fs::write(cache_config_path, toml).context("write cache config")?;

    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let cache =
            Cache::from_file(Some(cache_config_path)).context("load wasmtime cache config")?;
        config.cache(Some(cache));
        let engine = Engine::new(&config).context("create wasmtime engine (with cache)")?;
        let start = Instant::now();
        let _component = Component::from_binary(&engine, wasm_bytes)
            .context("compile component (with cache)")?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let first_run_ms = samples.first().copied().unwrap_or(0.0);
    let warm_samples: Vec<f64> = samples.iter().skip(1).copied().collect();
    let warm = stats_from_samples(&warm_samples);
    Ok(WithDiskCache {
        first_run_ms,
        warm,
    })
}

fn parse_label_path(spec: &str) -> Result<(String, PathBuf)> {
    let (label, path) = spec
        .split_once('=')
        .with_context(|| format!("expected LABEL=PATH, got `{spec}`"))?;
    if label.is_empty() || path.is_empty() {
        anyhow::bail!("LABEL and PATH must both be non-empty in `{spec}`");
    }
    Ok((label.to_string(), PathBuf::from(path)))
}

fn main() -> Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.bench_dir).context("create bench dir")?;
    let configs_dir = args.bench_dir.join("configs");
    let caches_dir = args.bench_dir.join("caches");

    let mut components_map = serde_json::Map::new();
    println!(
        "wasmtime-compile-bench: runs_per_regime={} components={}",
        args.runs,
        args.components.len()
    );

    for spec in &args.components {
        let (label, wasm_path) = parse_label_path(spec)?;
        let bytes = std::fs::read(&wasm_path)
            .with_context(|| format!("read wasm component for {label} at {}", wasm_path.display()))?;
        let wasm_bytes = bytes.len() as u64;
        println!(
            "\n[{label}] {} ({wasm_bytes} B / {:.2} MiB)",
            wasm_path.display(),
            wasm_bytes as f64 / 1_048_576.0
        );

        let no_cache = measure_no_cache(&bytes, args.runs)?;
        println!(
            "  no_cache:        runs={} mean={:.1} ms  std={:.1} ms  min={:.1}  max={:.1}",
            no_cache.runs, no_cache.mean_ms, no_cache.std_ms, no_cache.min_ms, no_cache.max_ms,
        );

        let with_cache = measure_with_disk_cache(
            &bytes,
            args.runs,
            &caches_dir.join(&label),
            &configs_dir.join(format!("{label}.toml")),
        )?;
        println!(
            "  with_disk_cache: first_run={:.1} ms (cold compile + populate); warm runs={} mean={:.1} ms  std={:.1} ms  min={:.1}  max={:.1}",
            with_cache.first_run_ms,
            with_cache.warm.runs,
            with_cache.warm.mean_ms,
            with_cache.warm.std_ms,
            with_cache.warm.min_ms,
            with_cache.warm.max_ms,
        );

        let entry = ComponentEntry {
            wasm_path: wasm_path.display().to_string(),
            wasm_bytes,
            no_cache,
            with_disk_cache: with_cache,
        };
        components_map.insert(label, serde_json::to_value(entry)?);
    }

    let output = Output {
        wasmtime_version: env!("CARGO_PKG_VERSION").to_string()
            + " (wasmtime crate "
            + WASMTIME_CRATE_VERSION
            + ")",
        runs_per_regime: args.runs,
        components: components_map,
    };

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut bytes = serde_json::to_vec_pretty(&output).context("serialize output JSON")?;
    bytes.push(b'\n');
    std::fs::write(&args.output, &bytes)
        .with_context(|| format!("write {}", args.output.display()))?;
    println!("\nwrote {}", args.output.display());

    Ok(())
}

const WASMTIME_CRATE_VERSION: &str = "41";
