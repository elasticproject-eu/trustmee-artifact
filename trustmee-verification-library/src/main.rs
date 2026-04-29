use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

#[derive(Parser, Debug)]
#[command(name = "wasm-verification-component")]
#[command(about = "TrustMee attestation verifier for CMW-wrapped EAT input")]
struct Args {
    /// Path to CMW input file containing a TrustMee EAT and endorsements
    #[arg(long, conflicts_with_all = ["component", "evidence"])]
    input: Option<PathBuf>,

    /// Path to verifier component (.wasm)
    #[arg(long)]
    component: Option<PathBuf>,

    /// Path to evidence input file
    #[arg(long)]
    evidence: Option<PathBuf>,

    /// Cache directory pre-opened to the component as `cache/`
    #[arg(long, default_value = ".wasm-verification-component-cache")]
    cache_dir: PathBuf,

    /// Optional PCCS URL used by TDX verifier components
    #[arg(long)]
    pccs_url: Option<String>,

    /// Optional OCI repository override used to fetch verifier components by component_id
    #[arg(long)]
    component_repository_hint: Option<String>,

    /// Optional JSON trust store used to verify component signatures and execution policy
    #[arg(long)]
    component_trust_store: Option<PathBuf>,

    /// Print compact one-line JSON
    #[arg(long)]
    compact: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let verifier = WasmVerificationComponent::new()?;

    let options = VerifyOptions {
        cache_dir: args.cache_dir,
        pccs_url: args.pccs_url,
        component_repository_hint: args.component_repository_hint,
        component_trust_store: args.component_trust_store,
    };

    let result = match (args.input, args.component, args.evidence) {
        (Some(input), None, None) => verifier.verify_cmw_path(&input, None, None, &options)?,
        (None, Some(component), Some(evidence)) => {
            verifier.verify_paths(&component, &evidence, None, None, &options)?
        }
        _ => bail!("provide either `--input` or both `--component` and `--evidence`"),
    };
    if args.compact {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(())
}
