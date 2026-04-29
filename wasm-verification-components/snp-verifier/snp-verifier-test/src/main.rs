use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sev::{
    firmware::{
        guest::AttestationReport,
        host::{CertTableEntry, CertType},
    },
    parser::ByteParser,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Store};
use wasmtime_wasi::p2::{IoView, WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!({
    path: "../snp-verifier-component/wit",
    world: "verifier",
});

#[derive(Parser, Debug)]
#[command(name = "snp-verifier-test")]
struct Args {
    /// Path to the Wasm component (`.wasm`) built by `cargo build --target wasm32-wasip2 --release`.
    #[arg(long)]
    component: PathBuf,

    /// Path to SNP evidence JSON (attestation_report + optional cert_chain).
    #[arg(long, conflicts_with_all = ["report", "vcek", "vlek"])]
    evidence_json: Option<PathBuf>,

    /// Path to an SNP attestation report (raw bytes).
    #[arg(
        long,
        required_unless_present = "evidence_json",
        conflicts_with = "evidence_json"
    )]
    report: Option<PathBuf>,

    /// Optional path to a VCEK certificate (DER bytes).
    #[arg(long)]
    vcek: Option<PathBuf>,

    /// Optional path to a VLEK certificate (DER bytes).
    #[arg(long)]
    vlek: Option<PathBuf>,

    /// Base cache directory on the host; a fresh subdirectory is pre-opened to the guest as `cache/`.
    #[arg(long, default_value = ".snp-verifier-cache")]
    cache_dir: PathBuf,

    /// Expected REPORT_DATA binding (hex string, <= 64 bytes; padded/truncated).
    #[arg(long)]
    expected_report_data_hex: Option<String>,

    /// Expected HOST_DATA binding (hex string, <= 32 bytes; padded/truncated).
    #[arg(long)]
    expected_init_data_hash_hex: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context("decode hex")
}

static CACHE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_cache_dir(base: &Path) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    let seq = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = base.join(format!("snp-vcek-cache-{nanos:x}-{pid}-{seq}"));
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

fn infer_media_type(bytes: &[u8]) -> &'static str {
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte == b'{' || byte == b'[')
        .unwrap_or(false)
    {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.component.exists() {
        bail!("component not found: {}", args.component.display());
    }
    if args.vcek.is_some() && args.vlek.is_some() {
        bail!("use only one of --vcek or --vlek");
    }

    let evidence_bytes = if let Some(path) = args.evidence_json.as_ref() {
        std::fs::read(path).with_context(|| format!("read {}", path.display()))?
    } else {
        let report_path = args
            .report
            .as_ref()
            .ok_or_else(|| anyhow!("--report is required unless --evidence-json is used"))?;
        let report_bytes = std::fs::read(report_path)
            .with_context(|| format!("read {}", report_path.display()))?;
        let attestation_report =
            AttestationReport::from_bytes(&report_bytes).context("parse SNP attestation report")?;

        let cert_chain = match (args.vcek.as_ref(), args.vlek.as_ref()) {
            (Some(path), None) => {
                let vcek =
                    std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
                Some(vec![CertTableEntry {
                    cert_type: CertType::VCEK,
                    data: vcek,
                }])
            }
            (None, Some(path)) => {
                let vlek =
                    std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
                Some(vec![CertTableEntry {
                    cert_type: CertType::VLEK,
                    data: vlek,
                }])
            }
            _ => None,
        };

        let evidence = SnpEvidence {
            attestation_report,
            cert_chain,
        };
        serde_json::to_vec(&evidence).context("serialize evidence JSON")?
    };

    std::fs::create_dir_all(&args.cache_dir)
        .with_context(|| format!("create {}", args.cache_dir.display()))?;
    let cache_dir = unique_cache_dir(&args.cache_dir)?;

    let expected_report_data = match args.expected_report_data_hex.as_deref() {
        Some(s) => {
            exports::trustee::verifier::verifier_interface::OptionalData::Value(decode_hex(s)?)
        }
        None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
    };
    let expected_init_data_hash = match args.expected_init_data_hash_hex.as_deref() {
        Some(s) => {
            exports::trustee::verifier::verifier_interface::OptionalData::Value(decode_hex(s)?)
        }
        None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
    };

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = wasmtime::Engine::new(&config)?;

    let component = Component::from_file(&engine, &args.component)
        .with_context(|| format!("load component {}", args.component.display()))?;

    let mut linker = Linker::<HostState>::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker)?;

    let state = HostState::new(&cache_dir)?;
    let mut store = Store::new(&engine, state);

    let bindings = Verifier::instantiate(&mut store, &component, &linker)?;
    let verifier_iface = bindings.trustee_verifier_verifier_interface();
    let verifier = verifier_iface.verifier();
    let verifier_resource = verifier.call_constructor(&mut store)?;
    let verifier_input = exports::trustee::verifier::verifier_interface::VerifierInput {
        evidence: evidence_bytes.clone(),
        evidence_media_type: infer_media_type(&evidence_bytes).to_string(),
        endorsements: Vec::new(),
    };
    let out = verifier.call_evaluate(
        &mut store,
        verifier_resource,
        &verifier_input,
        &expected_report_data,
        &expected_init_data_hash,
    )?;

    let value: serde_json::Value =
        serde_json::from_str(&out).context("component returned non-JSON string")?;
    if let Some(err) = value.get("error") {
        eprintln!("{value}");
        return Err(anyhow!("attestation failed: {err}"));
    }

    println!("{value}");
    Ok(())
}

// ---- Host plumbing (WASI Preview2 + WASI-HTTP) ----

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: wasmtime_wasi_http::WasiHttpCtx,
}

impl HostState {
    fn new(cache_dir: &Path) -> Result<Self> {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();

        // Pre-open the cache dir as `cache/` for the component.
        use wasmtime_wasi::{DirPerms, FilePerms};
        wasi.preopened_dir(cache_dir, "cache", DirPerms::all(), FilePerms::all())
            .with_context(|| format!("preopen {}", cache_dir.display()))?;

        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
        })
    }
}

impl IoView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.http
    }
}
