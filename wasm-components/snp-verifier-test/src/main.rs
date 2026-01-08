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
use std::path::PathBuf;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Store};

wasmtime::component::bindgen!({
    path: "../snp-verifier-component/wit",
    world: "verifier",
});

#[derive(Parser, Debug)]
#[command(name = "snp-verifier-test")]
struct Args {
    /// Path to the Wasm component (`.wasm`) built by `cargo component build`.
    #[arg(long)]
    component: PathBuf,

    /// Path to an SNP attestation report (raw bytes).
    #[arg(long)]
    report: PathBuf,

    /// Optional path to a VCEK certificate (DER bytes).
    #[arg(long)]
    vcek: Option<PathBuf>,

    /// Optional path to a VLEK certificate (DER bytes).
    #[arg(long)]
    vlek: Option<PathBuf>,

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

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.component.exists() {
        bail!("component not found: {}", args.component.display());
    }
    if args.vcek.is_some() && args.vlek.is_some() {
        bail!("use only one of --vcek or --vlek");
    }

    let report_bytes =
        std::fs::read(&args.report).with_context(|| format!("read {}", args.report.display()))?;
    let attestation_report = AttestationReport::from_bytes(&report_bytes)
        .context("parse SNP attestation report")?;

    let cert_chain = match (args.vcek.as_ref(), args.vlek.as_ref()) {
        (Some(path), None) => {
            let vcek = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            Some(vec![CertTableEntry {
                cert_type: CertType::VCEK,
                data: vcek,
            }])
        }
        (None, Some(path)) => {
            let vlek = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
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
    let evidence_bytes = serde_json::to_vec(&evidence).context("serialize evidence JSON")?;

    let expected_report_data = match args.expected_report_data_hex.as_deref() {
        Some(s) => exports::trustee::verifier::verifier_interface::OptionalData::Value(decode_hex(s)?),
        None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
    };
    let expected_init_data_hash = match args.expected_init_data_hash_hex.as_deref() {
        Some(s) => exports::trustee::verifier::verifier_interface::OptionalData::Value(decode_hex(s)?),
        None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
    };

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = wasmtime::Engine::new(&config)?;

    let component = Component::from_file(&engine, &args.component)
        .with_context(|| format!("load component {}", args.component.display()))?;

    let mut linker = Linker::<HostState>::new(&engine);
    wasmtime_wasi::add_to_linker_sync(&mut linker)?;
    wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker)?;

    let state = HostState::new()?;
    let mut store = Store::new(&engine, state);

    let bindings = Verifier::instantiate(&mut store, &component, &linker)?;
    let verifier_iface = bindings.trustee_verifier_verifier_interface();
    let verifier = verifier_iface.verifier();
    let verifier_resource = verifier.call_constructor(&mut store)?;
    let out = verifier.call_evaluate(
        &mut store,
        verifier_resource,
        &evidence_bytes,
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
    wasi: wasmtime_wasi::WasiCtx,
    http: wasmtime_wasi_http::WasiHttpCtx,
}

impl HostState {
    fn new() -> Result<Self> {
        let mut wasi = wasmtime_wasi::WasiCtxBuilder::new();
        wasi.inherit_stdio();

        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
        })
    }
}

impl wasmtime_wasi::WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.wasi
    }
}

impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.http
    }
}
