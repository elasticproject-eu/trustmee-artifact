use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::Parser;
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Store};

wasmtime::component::bindgen!({
    path: "../tdx-verifier-component/wit",
    world: "verifier",
});

#[derive(Parser, Debug)]
#[command(name = "tdx-verifier-test")]
struct Args {
    /// Path to the Wasm component (`.wasm`) built by `cargo build --target wasm32-wasip2 --release`.
    #[arg(long)]
    component: PathBuf,

    /// Path to a TDX quote (raw bytes).
    #[arg(long)]
    quote: PathBuf,

    /// Optional path to a CCEL (raw bytes).
    #[arg(long)]
    ccel: Option<PathBuf>,

    /// Optional PCCS/PCS base URL (defaults to Intel PCS).
    #[arg(long)]
    pccs_url: Option<String>,

    /// Cache directory on the host; will be pre-opened to the guest as `cache/`.
    #[arg(long, default_value = ".tdx-verifier-cache")]
    cache_dir: PathBuf,

    /// Expected REPORT_DATA binding (hex string, <= 64 bytes; zero-padded to 64).
    #[arg(long)]
    expected_report_data_hex: Option<String>,

    /// Expected MRCONFIGID binding (hex string, <= 48 bytes; zero-padded to 48).
    #[arg(long)]
    expected_init_data_hash_hex: Option<String>,
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
    let quote = std::fs::read(&args.quote).with_context(|| format!("read {}", args.quote.display()))?;
    let ccel = match &args.ccel {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("read {}", p.display()))?),
        None => None,
    };

    std::fs::create_dir_all(&args.cache_dir)
        .with_context(|| format!("create {}", args.cache_dir.display()))?;

    let evidence_json = serde_json::json!({
        "quote": base64::engine::general_purpose::STANDARD.encode(&quote),
        "cc_eventlog": ccel.as_ref().map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
    });
    let evidence_bytes = serde_json::to_vec(&evidence_json).context("serialize evidence JSON")?;

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

    // WASI + WASI-HTTP host state.
    let mut linker = Linker::<HostState>::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker)?;

    let state = HostState::new(&args.cache_dir, args.pccs_url.as_deref())?;
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

    // Convention: component returns a JSON object. On failure it returns
    // `{"status":"failed","error":"..."}` instead of trapping.
    let value: serde_json::Value = serde_json::from_str(&out).context("component returned non-JSON string")?;
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
    fn new(cache_dir: &Path, pccs_url: Option<&str>) -> Result<Self> {
        let mut wasi = wasmtime_wasi::WasiCtxBuilder::new();
        wasi.inherit_stdio();
        wasi.env("DCAP_QVL_CACHE_DIR", "cache");
        if let Some(url) = pccs_url {
            wasi.env("PCCS_URL", url);
        }

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

impl wasmtime_wasi::WasiView for HostState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
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
