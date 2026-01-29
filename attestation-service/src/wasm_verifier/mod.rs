use crate::config::{Config, WasmVerifierConfig};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;
use wasmsign2::PublicKeySet;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

wasmtime::component::bindgen!({
    path: "../wasm-components/tdx-verifier-component/wit",
    world: "verifier",
    async: true,
});

pub struct WasmVerifierHost {
    engine: Engine,
    cfg: ResolvedConfig,
    trusted_keys: Option<PublicKeySet>,
    registry: RwLock<RegistryState>,
}

#[derive(Clone)]
struct ResolvedConfig {
    allow_unsigned: bool,
    registry_dir: PathBuf,
    wasi_cache_dir: PathBuf,
}

#[derive(Default)]
struct RegistryState {
    by_id: HashMap<String, RegistryEntry>,
    by_hash: HashMap<String, String>,
    compiled: HashMap<String, Component>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RegistryIndex {
    by_id: HashMap<String, RegistryEntry>,
    by_hash: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RegistryEntry {
    component_id: String,
    sha256: String,
    filename: String,
}

impl WasmVerifierHost {
    pub async fn new(config: &Config) -> Result<Option<Self>> {
        if !config.wasm_verifier.enabled {
            return Ok(None);
        }

        let wasm_cfg: &WasmVerifierConfig = &config.wasm_verifier;
        let registry_dir = wasm_cfg
            .registry_dir
            .clone()
            .unwrap_or_else(|| config.work_dir.join("components"));
        let wasi_cache_dir = wasm_cfg
            .wasi_cache_dir
            .clone()
            .unwrap_or_else(|| config.work_dir.join("wasm-cache"));

        tokio::fs::create_dir_all(&registry_dir)
            .await
            .with_context(|| format!("create {}", registry_dir.display()))?;
        tokio::fs::create_dir_all(&wasi_cache_dir)
            .await
            .with_context(|| format!("create {}", wasi_cache_dir.display()))?;

        let mut wasmtime_cfg = wasmtime::Config::new();
        wasmtime_cfg.wasm_component_model(true);
        wasmtime_cfg.async_support(true);

        // Enable Wasmtime compilation caching if a config path is provided.
        // If unset, create a default config under `<work_dir>/wasmtime-cache.toml`.
        let cache_config_path = wasm_cfg
            .wasmtime_cache_config
            .clone()
            .unwrap_or_else(|| config.work_dir.join("wasmtime-cache.toml"));
        if let Some(parent) = cache_config_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }

        let cache_dir = config.work_dir.join("wasmtime-cache");
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .with_context(|| format!("create {}", cache_dir.display()))?;

        // Minimal config file for wasmtime's cache.
        // See: https://bytecodealliance.github.io/wasmtime/cli-cache.html
        let cache_toml = format!(
            "[cache]\n\
enabled = true\n\
directory = \"{}\"\n",
            cache_dir.display()
        );
        if tokio::fs::metadata(&cache_config_path).await.is_err() {
            tokio::fs::write(&cache_config_path, cache_toml)
                .await
                .with_context(|| format!("write {}", cache_config_path.display()))?;
        }

        // `cache_config_load` requires wasmtime's `cache` feature (enabled in Cargo.toml).
        wasmtime_cfg
            .cache_config_load(&cache_config_path)
            .with_context(|| format!("load wasmtime cache config {}", cache_config_path.display()))?;

        let engine = Engine::new(&wasmtime_cfg).context("create wasmtime engine")?;

        let trusted_keys = if wasm_cfg.allow_unsigned {
            None
        } else {
            let mut set = PublicKeySet::empty();
            for path in &wasm_cfg.trusted_public_keys {
                set.insert_any_file(path)
                    .map_err(|e| anyhow!("load trusted key {}: {e}", path.display()))?;
            }
            if set.is_empty() {
                bail!(
                    "wasm_verifier.enabled is true and allow_unsigned is false, but no trusted_public_keys are configured"
                );
            }
            Some(set)
        };

        let cfg = ResolvedConfig {
            allow_unsigned: wasm_cfg.allow_unsigned,
            registry_dir,
            wasi_cache_dir,
        };

        let registry = load_registry_index(&cfg.registry_dir).await?;

        Ok(Some(Self {
            engine,
            cfg,
            trusted_keys,
            registry: RwLock::new(registry),
        }))
    }

    pub async fn register_component(&self, component_bytes: &[u8]) -> Result<String> {
        self.verify_component_signature(component_bytes)
            .context("verify component signature")?;

        let sha256 = sha256_hex(component_bytes);

        // Fast path: already registered.
        {
            let state = self.registry.read().await;
            if let Some(existing) = state.by_hash.get(&sha256) {
                return Ok(existing.clone());
            }
        }

        // Compile once to validate the component before persisting.
        let compiled =
            Component::from_binary(&self.engine, component_bytes).context("compile component")?;

        let component_id = Uuid::new_v4().to_string();
        let filename = format!("{component_id}.wasm");
        let path = self.cfg.registry_dir.join(&filename);

        tokio::fs::write(&path, component_bytes)
            .await
            .with_context(|| format!("write {}", path.display()))?;

        let index_to_persist = {
            let mut state = self.registry.write().await;

            if let Some(existing) = state.by_hash.get(&sha256).cloned() {
                // Raced with another writer; keep the original registration.
                drop(state);
                let _ = tokio::fs::remove_file(&path).await;
                return Ok(existing);
            }

            state.by_id.insert(
                component_id.clone(),
                RegistryEntry {
                    component_id: component_id.clone(),
                    sha256: sha256.clone(),
                    filename,
                },
            );
            state.by_hash.insert(sha256, component_id.clone());
            state.compiled.insert(component_id.clone(), compiled);

            RegistryIndex {
                by_id: state.by_id.clone(),
                by_hash: state.by_hash.clone(),
            }
        };

        persist_registry_index(&self.cfg.registry_dir, &index_to_persist).await?;

        info!(component_id, "registered wasm component verifier");
        Ok(component_id)
    }

    pub async fn get_component_bytes(&self, component_id: &str) -> Result<Vec<u8>> {
        let entry = {
            let state = self.registry.read().await;
            state
                .by_id
                .get(component_id)
                .cloned()
                .with_context(|| format!("unknown component_id {component_id}"))?
        };

        let path = self.cfg.registry_dir.join(entry.filename);
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("read {}", path.display()))
    }

    pub async fn evaluate(
        &self,
        component_id: Option<&str>,
        component_bytes: Option<&[u8]>,
        evidence_json: &Value,
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
    ) -> Result<Value> {
        let component = self
            .resolve_component(component_id, component_bytes)
            .await
            .context("resolve component")?;

        let evidence_bytes = serde_json::to_vec(evidence_json).context("serialize evidence JSON")?;

        let expected_report = match expected_report_data {
            Some(v) => exports::trustee::verifier::verifier_interface::OptionalData::Value(v.to_vec()),
            None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
        };
        let expected_init = match expected_init_data_hash {
            Some(v) => exports::trustee::verifier::verifier_interface::OptionalData::Value(v.to_vec()),
            None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
        };

        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;

        let host_state = HostState::new(&self.cfg.wasi_cache_dir)?;
        let mut store = Store::new(&self.engine, host_state);

        let bindings = Verifier::instantiate_async(&mut store, &component, &linker).await?;
        let iface = bindings.trustee_verifier_verifier_interface();
        let verifier = iface.verifier();
        let verifier_resource = verifier.call_constructor(&mut store).await?;
        let out = verifier
            .call_evaluate(
                &mut store,
                verifier_resource,
                &evidence_bytes,
                &expected_report,
                &expected_init,
            )
            .await?;

        let value: Value = serde_json::from_str(&out).context("component returned non-JSON string")?;
        if value.get("error").is_some() {
            return Err(anyhow!("wasm verifier reported failure: {value}"));
        }

        Ok(value)
    }

    async fn resolve_component(
        &self,
        component_id: Option<&str>,
        component_bytes: Option<&[u8]>,
    ) -> Result<Component> {
        if let Some(bytes) = component_bytes {
            // Attestation API path: verify signature, then register/dedupe and use cached compiled component.
            let id = self.register_component(bytes).await?;
            return self.get_compiled_component(&id).await;
        }

        let Some(component_id) = component_id else {
            bail!("no component_id or component bytes provided");
        };
        self.get_compiled_component(component_id).await
    }

    async fn get_compiled_component(&self, component_id: &str) -> Result<Component> {
        {
            let state = self.registry.read().await;
            if let Some(compiled) = state.compiled.get(component_id) {
                return Ok(compiled.clone());
            }
        }

        let bytes = self.get_component_bytes(component_id).await?;
        let compiled = Component::from_binary(&self.engine, &bytes).context("compile component")?;

        let mut state = self.registry.write().await;
        state.compiled.insert(component_id.to_string(), compiled.clone());
        Ok(compiled)
    }

    fn verify_component_signature(&self, component_bytes: &[u8]) -> Result<()> {
        if self.cfg.allow_unsigned {
            warn!("wasm component signature verification disabled (allow_unsigned = true)");
            return Ok(());
        }
        let Some(keys) = &self.trusted_keys else {
            bail!("no trusted keys configured");
        };
        let mut reader = Cursor::new(component_bytes);
        keys.verify(&mut reader, None)
            .map_err(|e| anyhow!("component signature invalid: {e}"))?;
        Ok(())
    }
}

impl HostState {
    fn new(wasi_cache_dir: &Path) -> Result<Self> {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        wasi.env("DCAP_QVL_CACHE_DIR", "cache");
        if let Ok(v) = std::env::var("AS_VERIFICATION_TIMING_JSON") {
            wasi.env("AS_VERIFICATION_TIMING_JSON", v);
        }
        if let Ok(v) = std::env::var("SNP_STEP_TIMING_JSON") {
            wasi.env("SNP_STEP_TIMING_JSON", v);
        }
        if let Ok(v) = std::env::var("SNP_TIMING_MODE") {
            wasi.env("SNP_TIMING_MODE", v);
        }
        wasi.preopened_dir(wasi_cache_dir, "cache", DirPerms::all(), FilePerms::all())
            .with_context(|| format!("preopen {}", wasi_cache_dir.display()))?;

        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: WasiHttpCtx::new(),
        })
    }
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
}

impl WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl WasiHttpView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

async fn load_registry_index(registry_dir: &Path) -> Result<RegistryState> {
    let index_path = registry_dir.join("index.json");
    let bytes = match tokio::fs::read(&index_path).await {
        Ok(b) => b,
        Err(_) => return Ok(RegistryState::default()),
    };
    let idx: RegistryIndex =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", index_path.display()))?;

    // Validate that referenced component files exist.
    let mut state = RegistryState::default();
    for (id, entry) in idx.by_id {
        let path = registry_dir.join(&entry.filename);
        if tokio::fs::metadata(&path).await.is_err() {
            warn!(
                component_id = id,
                path = %path.display(),
                "registry entry file missing; skipping"
            );
            continue;
        }
        state.by_hash.insert(entry.sha256.clone(), entry.component_id.clone());
        state.by_id.insert(id, entry);
    }
    // Prefer by_hash from reconstructed by_id to avoid stale entries.
    if !idx.by_hash.is_empty() {
        debug!("loaded wasm component registry index");
    }
    Ok(state)
}

async fn persist_registry_index(registry_dir: &Path, index: &RegistryIndex) -> Result<()> {
    let data = serde_json::to_vec_pretty(index).context("serialize registry index")?;
    let path = registry_dir.join("index.json");
    let tmp = registry_dir.join("index.json.tmp");
    tokio::fs::write(&tmp, data)
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
