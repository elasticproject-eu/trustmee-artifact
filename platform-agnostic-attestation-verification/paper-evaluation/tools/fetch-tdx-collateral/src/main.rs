//! Fetch TDX collateral from Intel PCS (or a configured PCCS) and emit it as
//! a CBOR-encoded QuoteCollateralV3 suitable for inclusion in a TrustMee CMW
//! endorsement with media type `application/vnd.trustmee.tdx-collateral+cbor`.

use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "fetch-tdx-collateral")]
#[command(about = "Fetch TDX collateral and CBOR-encode for CMW endorsement")]
struct Args {
    /// Path to a TDX evidence JSON file (base64-encoded `quote`) or a raw
    /// quote binary.
    #[arg(long)]
    quote: PathBuf,

    /// Where to write the CBOR-encoded collateral.
    #[arg(long)]
    output: PathBuf,

    /// Optional PCCS/PCS URL (default: Intel PCS).
    #[arg(long)]
    pccs_url: Option<String>,

    /// Cache dir for dcap-qvl-wasi (the fetcher caches its own JSON files
    /// here; safe to delete any time).
    #[arg(long, default_value = "/tmp/fetch-tdx-collateral-cache")]
    cache_dir: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    fs::create_dir_all(&args.cache_dir)
        .with_context(|| format!("create cache dir {}", args.cache_dir.display()))?;

    let raw = fs::read(&args.quote)
        .with_context(|| format!("read quote from {}", args.quote.display()))?;

    let quote_bin = resolve_quote_bytes(&raw)?;
    let collateral =
        dcap_qvl_wasi::get_collateral_cached(args.pccs_url.as_deref(), &quote_bin, &args.cache_dir)
            .context("dcap-qvl collateral fetch")?;

    let mut out = Vec::new();
    ciborium::ser::into_writer(&collateral, &mut out).context("CBOR-encode QuoteCollateralV3")?;
    fs::write(&args.output, &out)
        .with_context(|| format!("write collateral to {}", args.output.display()))?;

    eprintln!(
        "fetched {} bytes of TDX collateral into {}",
        out.len(),
        args.output.display()
    );
    Ok(())
}

/// Accept either a raw binary quote or a TDX-evidence JSON blob that contains
/// a base64 `quote` field.
fn resolve_quote_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    if let Ok(as_str) = std::str::from_utf8(raw) {
        let trimmed = as_str.trim_start();
        if trimmed.starts_with('{') {
            #[derive(serde::Deserialize)]
            struct Ev {
                quote: String,
            }
            let ev: Ev = serde_json::from_str(trimmed).context("parse evidence JSON")?;
            return base64::engine::general_purpose::STANDARD
                .decode(ev.quote)
                .context("base64-decode quote field");
        }
    }
    Ok(raw.to_vec())
}
