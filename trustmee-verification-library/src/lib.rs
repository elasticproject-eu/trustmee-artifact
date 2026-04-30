use anyhow::{anyhow, bail, Context, Result};
use component_signature::{
    component_bytes_before_signature, resolve_execution_policy_for_cmw,
    resolve_execution_policy_for_direct, ExecutionPolicy,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::SystemTime,
};
use trustmee_input::{ComponentVerifierInput, ParsedCmwInput};
use wasmtime::component::{Component, HasSelf, Linker, ResourceAny, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::WasiCtxView;
use wasmtime_wasi_http::{
    bindings::http::types::ErrorCode as WasiHttpErrorCode,
    body::HyperOutgoingBody,
    types::{default_send_request, HostFutureIncomingResponse, OutgoingRequestConfig},
};

mod component_signature;
mod host_crypto;
mod trustmee_input;

pub use host_crypto::{
    verify_snp_crypto_host, HostProcessorGeneration, HostVekKind, HostVerifiedVekMeta,
};
pub use trustmee_input::{
    DEFAULT_COMPONENT_OCI_BASE, SNP_COLLATERAL_MEDIA_TYPE, TDX_COLLATERAL_MEDIA_TYPE,
    TRUSTMEE_COLLECTION_TYPE, TRUSTMEE_EAT_PROFILE,
};

pub const TRUSTMEE_OUTPUT_EAT_PROFILE: &str = "https://trustmee.invalid/eat/verification-result";

wasmtime::component::bindgen!({
    path: "wit",
    world: "verifier",
});

const DEFAULT_CACHE_DIR: &str = ".wasm-verification-component-cache";
const DEFAULT_COMPILED_COMPONENT_CACHE_SUBDIR: &str = "wasmtime-compiled-components";
const DEFAULT_COMPILED_COMPONENT_CACHE_CONFIG: &str = "wasmtime-cache-config.toml";
const TEE_TYPE_CLAIM: &str = "tee_type";
const TRUSTMEE_CLAIMS_KEY: &str = "claims";
const VERIFIER_COMPONENT_SHA256_CLAIM: &str = "verifier_component_sha256";
const VERIFIER_COMPONENT_SIGNATURE_PUBLIC_KEY_CLAIM: &str =
    "verifier_component_signature_public_key";
const COMPONENT_TIMING_CLAIMS: &[&str] = &[
    "collateral_fetch_ms",
    "wasm_verify_ms",
    "cert_chain_ms",
    "signature_ms",
    "others_ms",
    "total_ms",
];
const TRUSTMEE_WASM_DISABLE_INMEM_CACHE_ENV: &str = "TRUSTMEE_WASM_DISABLE_INMEM_CACHE";
const TRUSTMEE_WASM_INMEM_CACHE_MODE_ENV: &str = "TRUSTMEE_WASM_INMEM_CACHE_MODE";
const FORWARDED_WASM_ENV_KEYS: &[&str] = &[
    "WVC_EMIT_TIMING",
    "SNP_TIMING_MODE",
    "DCAP_QVL_DISABLE_CACHE",
    "DCAP_QVL_PCCS_URL",
    "SNP_VCEK_DISABLE_CACHE",
];

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub cache_dir: PathBuf,
    pub pccs_url: Option<String>,
    pub component_repository_hint: Option<String>,
    pub component_trust_store: Option<PathBuf>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            pccs_url: None,
            component_repository_hint: None,
            component_trust_store: None,
        }
    }
}

pub struct WasmVerificationComponent {
    engine: Engine,
    loaded_components: RwLock<HashMap<[u8; 32], LoadedWasmComponent>>,
}

#[derive(Clone)]
pub struct LoadedWasmComponent {
    inner: Arc<LoadedWasmComponentInner>,
}

impl LoadedWasmComponent {
    fn component_bytes(&self) -> &[u8] {
        &self.inner.component_bytes
    }
}

struct LoadedWasmComponentInner {
    pre: VerifierPre<HostState>,
    component_hash: [u8; 32],
    component_claim_hash: [u8; 32],
    component_bytes: Arc<[u8]>,
    instantiated_components:
        Mutex<HashMap<InstantiatedComponentKey, Arc<Mutex<InstantiatedWasmComponent>>>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InstantiatedComponentKey {
    component_hash: [u8; 32],
    cache_dir: PathBuf,
    fuel: u64,
    network_allowed: bool,
    forwarded_env: Vec<(String, String)>,
}

impl InstantiatedComponentKey {
    fn new(
        component_hash: [u8; 32],
        options: &VerifyOptions,
        execution_policy: &ExecutionPolicy,
    ) -> Self {
        Self {
            component_hash,
            cache_dir: options.cache_dir.clone(),
            fuel: execution_policy.fuel,
            network_allowed: execution_policy.network_allowed,
            forwarded_env: forwarded_wasm_env(),
        }
    }
}

struct InstantiatedWasmComponent {
    store: Store<HostState>,
    bindings: Verifier,
    verifier_resource: ResourceAny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InMemoryCacheMode {
    Disabled,
    Warm,
    Hot,
}

impl WasmVerificationComponent {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        let cache = wasmtime::Cache::from_file(Some(&ensure_default_compile_cache_config()?))
            .context("load wasmtime compiled component cache configuration")?;
        config.cache(Some(cache));

        let engine = Engine::new(&config).context("create wasmtime engine")?;
        Ok(Self {
            engine,
            loaded_components: RwLock::new(HashMap::new()),
        })
    }

    pub fn verify_bytes(
        &self,
        component_bytes: &[u8],
        evidence_bytes: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        std::fs::create_dir_all(&options.cache_dir)
            .with_context(|| format!("create {}", options.cache_dir.display()))?;

        let component = self
            .load_component(component_bytes)
            .context("load wasm verifier component")?;
        self.verify_loaded_component(
            &component,
            evidence_bytes,
            expected_report_data,
            expected_init_data_hash,
            options,
        )
    }

    pub fn verify_cmw_bytes(
        &self,
        cmw_bytes: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        let total_start = std::time::Instant::now();
        let ParsedCmwInput {
            component_id,
            stapled_component_records,
            verifier_input,
        } = trustmee_input::parse_cmw_input(cmw_bytes).context("parse CMW input")?;

        std::fs::create_dir_all(&options.cache_dir)
            .with_context(|| format!("create {}", options.cache_dir.display()))?;

        let component = match self.get_cached_component_for_component_id(&component_id)? {
            Some(component) => {
                if cache_trace_enabled() {
                    eprintln!("WVC verify_cmw_bytes: COMPILED MEMORY HIT for `{component_id}`");
                }
                component
            }
            None => {
                if cache_trace_enabled() {
                    eprintln!("WVC verify_cmw_bytes: COMPILED MEMORY MISS for `{component_id}`");
                }
                let component_bytes = trustmee_input::resolve_component_bytes(
                    &component_id,
                    stapled_component_records,
                    options,
                )
                .context("resolve verifier component")?;
                self.load_component(&component_bytes)
                    .context("load wasm verifier component from CMW input")?
            }
        };
        let execution_policy = resolve_execution_policy_for_cmw(
            component.component_bytes(),
            options.component_trust_store.as_deref(),
            SystemTime::now(),
        )
        .context("resolve verifier component execution policy")?;

        let result = self.verify_loaded_component_input(
            &component,
            verifier_input,
            expected_report_data,
            expected_init_data_hash,
            &execution_policy,
            options,
        )?;

        emit_wvc_timing("wvc_total_timing", ms_since(total_start));

        transform_trustmee_claims(result)
    }

    pub fn verify_cmw_path(
        &self,
        cmw_path: impl AsRef<Path>,
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        let cmw_path = cmw_path.as_ref();
        let cmw_bytes =
            std::fs::read(cmw_path).with_context(|| format!("read {}", cmw_path.display()))?;
        self.verify_cmw_bytes(
            &cmw_bytes,
            expected_report_data,
            expected_init_data_hash,
            options,
        )
    }

    pub fn load_component(&self, component_bytes: &[u8]) -> Result<LoadedWasmComponent> {
        let component_hash = hash_component(component_bytes);
        if let Some(component) = self.get_cached_component(&component_hash)? {
            if cache_trace_enabled() {
                eprintln!(
                    "WVC load_component: MEMORY HIT for component hash {:02x}{:02x}{:02x}{:02x}...",
                    component_hash[0], component_hash[1], component_hash[2], component_hash[3]
                );
            }
            return Ok(component);
        }

        if cache_trace_enabled() {
            eprintln!(
                "WVC load_component: MEMORY MISS for component hash {:02x}{:02x}{:02x}{:02x}...",
                component_hash[0], component_hash[1], component_hash[2], component_hash[3]
            );
        }
        let component_claim_hash =
            hash_verifier_component_claim(component_bytes).context("hash verifier component")?;

        let load_start = std::time::Instant::now();
        let component = Component::from_binary(&self.engine, component_bytes)
            .context("compile wasm verifier component")?;
        let pre = create_preloaded_bindings(&self.engine, &component)?;
        emit_wvc_timing("wvc_load_timing", ms_since(load_start));
        let loaded = LoadedWasmComponent {
            inner: Arc::new(LoadedWasmComponentInner {
                pre,
                component_hash,
                component_claim_hash,
                component_bytes: Arc::<[u8]>::from(component_bytes.to_vec()),
                instantiated_components: Mutex::new(HashMap::new()),
            }),
        };

        // Paper-eval: skip the insert too when the in-memory cache is
        // disabled, so memory doesn't grow unbounded across 50 requests.
        if inmem_cache_disabled() {
            return Ok(loaded);
        }

        let mut cached_components = self
            .loaded_components
            .write()
            .map_err(|_| anyhow!("component cache lock poisoned"))?;

        Ok(cached_components
            .entry(component_hash)
            .or_insert_with(|| loaded.clone())
            .clone())
    }

    pub fn verify_loaded_component(
        &self,
        component: &LoadedWasmComponent,
        evidence_bytes: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        let execution_policy = resolve_execution_policy_for_direct(
            component.component_bytes(),
            options.component_trust_store.as_deref(),
            SystemTime::now(),
        )
        .context("resolve verifier component execution policy")?;
        self.verify_loaded_component_input(
            component,
            legacy_verifier_input(evidence_bytes),
            expected_report_data,
            expected_init_data_hash,
            &execution_policy,
            options,
        )
    }

    pub fn verify_loaded_component_with_expected_data(
        &self,
        component: &LoadedWasmComponent,
        evidence_bytes: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        self.verify_loaded_component(
            component,
            evidence_bytes,
            expected_report_data,
            expected_init_data_hash,
            options,
        )
    }

    fn verify_loaded_component_input(
        &self,
        component: &LoadedWasmComponent,
        verifier_input: ComponentVerifierInput,
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        execution_policy: &ExecutionPolicy,
        options: &VerifyOptions,
    ) -> Result<Value> {
        std::fs::create_dir_all(&options.cache_dir)
            .with_context(|| format!("create {}", options.cache_dir.display()))?;

        let instance = self
            .get_instantiated_component(component, execution_policy, options)
            .context("get instantiated wasm verifier component")?;
        let mut instance = instance
            .lock()
            .map_err(|_| anyhow!("instantiated component lock poisoned"))?;
        instance.verify(
            verifier_input,
            expected_report_data,
            expected_init_data_hash,
            execution_policy,
            options,
            &component.inner.component_claim_hash,
        )
    }

    pub fn verify_paths(
        &self,
        component_path: impl AsRef<Path>,
        evidence_path: impl AsRef<Path>,
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        let component_path = component_path.as_ref();
        let evidence_path = evidence_path.as_ref();

        let component_bytes = std::fs::read(component_path)
            .with_context(|| format!("read {}", component_path.display()))?;
        let evidence_bytes = std::fs::read(evidence_path)
            .with_context(|| format!("read {}", evidence_path.display()))?;

        self.verify_bytes(
            &component_bytes,
            &evidence_bytes,
            expected_report_data,
            expected_init_data_hash,
            options,
        )
    }

    fn get_cached_component(
        &self,
        component_hash: &[u8; 32],
    ) -> Result<Option<LoadedWasmComponent>> {
        // Paper-eval hook: bypass the loaded/pre-instantiated memory cache
        // when the env toggle is set so each request recompiles (wasmtime
        // disk cache still applies).
        if inmem_cache_disabled() {
            return Ok(None);
        }
        let cached_components = self
            .loaded_components
            .read()
            .map_err(|_| anyhow!("component cache lock poisoned"))?;
        Ok(cached_components.get(component_hash).cloned())
    }

    fn get_cached_component_for_component_id(
        &self,
        component_id: &str,
    ) -> Result<Option<LoadedWasmComponent>> {
        let component_hash = trustmee_input::component_hash_for_id(component_id)
            .with_context(|| format!("decode component_id `{component_id}`"))?;
        self.get_cached_component(&component_hash)
    }

    fn get_instantiated_component(
        &self,
        component: &LoadedWasmComponent,
        execution_policy: &ExecutionPolicy,
        options: &VerifyOptions,
    ) -> Result<Arc<Mutex<InstantiatedWasmComponent>>> {
        if !instantiated_component_cache_enabled() {
            return Ok(Arc::new(Mutex::new(InstantiatedWasmComponent::new(
                &self.engine,
                &component.inner.pre,
                execution_policy,
                options,
            )?)));
        }

        let key = InstantiatedComponentKey::new(
            component.inner.component_hash,
            options,
            execution_policy,
        );

        let mut instantiated_components = component
            .inner
            .instantiated_components
            .lock()
            .map_err(|_| anyhow!("instantiated component cache lock poisoned"))?;

        if let Some(instance) = instantiated_components.get(&key) {
            if cache_trace_enabled() {
                eprintln!("WVC instantiated component cache: HIT");
            }
            return Ok(Arc::clone(instance));
        }

        if cache_trace_enabled() {
            eprintln!("WVC instantiated component cache: MISS");
        }

        let instance = Arc::new(Mutex::new(InstantiatedWasmComponent::new(
            &self.engine,
            &component.inner.pre,
            execution_policy,
            options,
        )?));
        instantiated_components.insert(key, Arc::clone(&instance));
        Ok(instance)
    }
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CACHE_DIR)
}

fn default_compile_cache_dir() -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("get current working directory")?;
    Ok(current_dir
        .join(DEFAULT_CACHE_DIR)
        .join(DEFAULT_COMPILED_COMPONENT_CACHE_SUBDIR))
}

fn default_compile_cache_config_path() -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("get current working directory")?;
    Ok(current_dir
        .join(DEFAULT_CACHE_DIR)
        .join(DEFAULT_COMPILED_COMPONENT_CACHE_CONFIG))
}

fn ensure_default_compile_cache_config() -> Result<PathBuf> {
    let cache_dir = default_compile_cache_dir()?;
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("create {}", cache_dir.display()))?;

    let config_path = default_compile_cache_config_path()?;
    let config_contents = format!("[cache]\ndirectory = \"{}\"\n", cache_dir.display());

    let needs_write = match std::fs::read_to_string(&config_path) {
        Ok(existing) => existing != config_contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(err) => return Err(err).with_context(|| format!("read {}", config_path.display())),
    };

    if needs_write {
        std::fs::write(&config_path, config_contents)
            .with_context(|| format!("write {}", config_path.display()))?;
    }

    Ok(config_path)
}

fn create_preloaded_bindings(
    engine: &Engine,
    component: &Component,
) -> Result<VerifierPre<HostState>> {
    let mut linker = Linker::<HostState>::new(engine);
    trustee::verifier::snp_host_crypto_interface::add_to_linker::<_, HasSelf<_>>(
        &mut linker,
        |state| state,
    )
    .context("link SNP host crypto interface")?;
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker).context("link wasi")?;
    wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker).context("link wasi-http")?;

    let instance_pre = linker
        .instantiate_pre(component)
        .context("create instance pre for verifier component")?;
    VerifierPre::new(instance_pre).context("create typed verifier pre bindings")
}

impl InstantiatedWasmComponent {
    fn new(
        engine: &Engine,
        pre: &VerifierPre<HostState>,
        execution_policy: &ExecutionPolicy,
        options: &VerifyOptions,
    ) -> Result<Self> {
        let state = HostState::new(&options.cache_dir, execution_policy.network_allowed)?;
        let mut store = Store::new(engine, state);
        store
            .set_fuel(execution_policy.fuel)
            .context("apply wasmtime fuel limit")?;

        let instantiate_start = std::time::Instant::now();
        let bindings = pre
            .instantiate(&mut store)
            .context("instantiate preloaded verifier component")?;
        emit_wvc_timing("wvc_instantiate_timing", ms_since(instantiate_start));

        let verifier_iface = bindings.trustee_verifier_verifier_interface();
        let verifier = verifier_iface.verifier();
        let verifier_resource = verifier
            .call_constructor(&mut store)
            .context("construct verifier resource")?;

        Ok(Self {
            store,
            bindings,
            verifier_resource,
        })
    }

    fn verify(
        &mut self,
        verifier_input: ComponentVerifierInput,
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        execution_policy: &ExecutionPolicy,
        options: &VerifyOptions,
        component_claim_hash: &[u8; 32],
    ) -> Result<Value> {
        self.store
            .set_fuel(execution_policy.fuel)
            .context("reset wasmtime fuel limit")?;

        let expected_report_data = match expected_report_data {
            Some(data) => {
                exports::trustee::verifier::verifier_interface::OptionalData::Value(data.to_vec())
            }
            None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
        };
        let expected_init_data_hash = match expected_init_data_hash {
            Some(data) => {
                exports::trustee::verifier::verifier_interface::OptionalData::Value(data.to_vec())
            }
            None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
        };

        let verifier_input =
            add_pccs_url_to_verifier_input(verifier_input, options.pccs_url.as_deref())
                .context("attach optional pccs_url to verifier input")?;
        let verifier_input = to_wit_verifier_input(verifier_input);

        let verifier_iface = self.bindings.trustee_verifier_verifier_interface();
        let verifier = verifier_iface.verifier();
        let verify_start = std::time::Instant::now();
        let out = verifier
            .call_evaluate(
                &mut self.store,
                self.verifier_resource,
                &verifier_input,
                &expected_report_data,
                &expected_init_data_hash,
            )
            .context("run attestation verification")?;
        emit_wvc_timing("wvc_verify_timing", ms_since(verify_start));

        let value: Value =
            serde_json::from_str(&out).context("component returned non-JSON output")?;
        if let Some(err) = value.get("error") {
            return Err(anyhow!("attestation verification failed: {err}"));
        }

        let mut value = add_verifier_component_claims(
            value,
            component_claim_hash,
            execution_policy
                .verifier_component_signature_public_key
                .as_deref(),
        );
        reemit_component_step_timings(&value);
        strip_component_timing_claims(&mut value);
        Ok(value)
    }
}

fn hash_component(component_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(component_bytes).into()
}

fn hash_verifier_component_claim(component_bytes: &[u8]) -> Result<[u8; 32]> {
    let component_bytes = component_bytes_before_signature(component_bytes)?;
    Ok(hash_component(component_bytes.as_ref()))
}

fn add_verifier_component_claims(
    mut value: Value,
    component_hash: &[u8; 32],
    signature_public_key: Option<&str>,
) -> Value {
    if let Some(claims) = value.as_object_mut() {
        claims.insert(
            VERIFIER_COMPONENT_SHA256_CLAIM.to_string(),
            Value::String(hex::encode(component_hash)),
        );
        if let Some(signature_public_key) = signature_public_key {
            claims.insert(
                VERIFIER_COMPONENT_SIGNATURE_PUBLIC_KEY_CLAIM.to_string(),
                Value::String(signature_public_key.to_string()),
            );
        }
    }

    value
}

fn transform_trustmee_claims(input_claims: Value) -> Result<Value> {
    let mut claims_map = input_claims
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("trustmee claims must be a JSON object"))?;

    let init_data = claims_map.remove("init_data");
    let report_data = claims_map.remove("report_data");
    let tee_type = remove_required_string_claim(&mut claims_map, TEE_TYPE_CLAIM)?;
    let verifier_component_sha256 =
        remove_required_string_claim(&mut claims_map, VERIFIER_COMPONENT_SHA256_CLAIM)?;
    let verifier_component_signature_public_key = remove_optional_string_claim(
        &mut claims_map,
        VERIFIER_COMPONENT_SIGNATURE_PUBLIC_KEY_CLAIM,
    )?;
    strip_component_timing_claims_from_map(&mut claims_map);

    let mut trustmee_claims = Map::new();
    trustmee_claims.insert(
        "eat_profile".to_string(),
        Value::String(TRUSTMEE_OUTPUT_EAT_PROFILE.to_string()),
    );
    if let Some(init_data) = init_data {
        trustmee_claims.insert("init_data".to_string(), init_data);
    }
    if let Some(report_data) = report_data {
        trustmee_claims.insert("report_data".to_string(), report_data);
    }
    trustmee_claims.insert(TEE_TYPE_CLAIM.to_string(), Value::String(tee_type));
    trustmee_claims.insert(TRUSTMEE_CLAIMS_KEY.to_string(), Value::Object(claims_map));
    trustmee_claims.insert(
        VERIFIER_COMPONENT_SHA256_CLAIM.to_string(),
        Value::String(verifier_component_sha256),
    );
    if let Some(public_key) = verifier_component_signature_public_key {
        trustmee_claims.insert(
            VERIFIER_COMPONENT_SIGNATURE_PUBLIC_KEY_CLAIM.to_string(),
            Value::String(public_key),
        );
    }

    Ok(Value::Object(trustmee_claims))
}

fn strip_component_timing_claims(value: &mut Value) {
    let Some(claims) = value.as_object_mut() else {
        return;
    };
    strip_component_timing_claims_from_map(claims);
    if let Some(nested_claims) = claims
        .get_mut(TRUSTMEE_CLAIMS_KEY)
        .and_then(Value::as_object_mut)
    {
        strip_component_timing_claims_from_map(nested_claims);
    }
}

fn strip_component_timing_claims_from_map(claims: &mut Map<String, Value>) {
    for claim in COMPONENT_TIMING_CLAIMS {
        claims.remove(*claim);
    }
}

fn remove_required_string_claim(
    claims_map: &mut Map<String, Value>,
    claim_name: &str,
) -> Result<String> {
    match claims_map.remove(claim_name) {
        Some(Value::String(value)) => Ok(value),
        Some(_) => bail!("trustmee claim `{claim_name}` must be a string"),
        None => bail!("trustmee claims must include `{claim_name}`"),
    }
}

fn remove_optional_string_claim(
    claims_map: &mut Map<String, Value>,
    claim_name: &str,
) -> Result<Option<String>> {
    match claims_map.remove(claim_name) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => bail!("trustmee claim `{claim_name}` must be a string"),
        None => Ok(None),
    }
}

fn cache_trace_enabled() -> bool {
    env_flag_enabled("TRUSTMEE_CACHE_TRACE")
}

fn forwarded_wasm_env() -> Vec<(String, String)> {
    FORWARDED_WASM_ENV_KEYS
        .iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| ((*key).to_string(), value))
        })
        .collect()
}

/// Paper-eval: bypass the in-memory loaded/pre-instantiated component cache.
/// Wasmtime's on-disk compilation cache still applies. This legacy switch
/// takes precedence over TRUSTMEE_WASM_INMEM_CACHE_MODE.
fn inmem_cache_disabled() -> bool {
    inmem_cache_mode() == InMemoryCacheMode::Disabled
}

fn instantiated_component_cache_enabled() -> bool {
    inmem_cache_mode() == InMemoryCacheMode::Hot
}

fn inmem_cache_mode() -> InMemoryCacheMode {
    if env_flag_enabled(TRUSTMEE_WASM_DISABLE_INMEM_CACHE_ENV) {
        return InMemoryCacheMode::Disabled;
    }

    match std::env::var(TRUSTMEE_WASM_INMEM_CACHE_MODE_ENV) {
        Ok(value) => parse_inmem_cache_mode(Some(&value)).unwrap_or_else(|| {
            if cache_trace_enabled() {
                eprintln!(
                    "WVC cache mode: unknown {TRUSTMEE_WASM_INMEM_CACHE_MODE_ENV}={value:?}; using warm"
                );
            }
            InMemoryCacheMode::Warm
        }),
        Err(_) => InMemoryCacheMode::Warm,
    }
}

fn parse_inmem_cache_mode(value: Option<&str>) -> Option<InMemoryCacheMode> {
    let value = value.unwrap_or("warm").trim();

    if value.is_empty() {
        return Some(InMemoryCacheMode::Warm);
    }

    match value.to_ascii_lowercase().as_str() {
        "cold" | "disabled" | "disable" | "off" | "none" => Some(InMemoryCacheMode::Disabled),
        "warm" | "pre" | "preinstantiate" | "preinstantiated" | "preloaded" => {
            Some(InMemoryCacheMode::Warm)
        }
        "hot" | "instantiated" | "instance" | "1" | "true" | "yes" => Some(InMemoryCacheMode::Hot),
        _ => None,
    }
}

fn env_flag_enabled(key: &str) -> bool {
    std::env::var(key)
        .map(|value| {
            value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

/// Paper-eval: emit WASM load / instantiate / verify / total timing events.
fn wasm_timing_enabled() -> bool {
    env_flag_enabled("WASM_TIMING_JSON")
}

fn emit_wvc_timing(event: &str, ms: f64) {
    if !wasm_timing_enabled() {
        return;
    }
    let line = serde_json::json!({
        "event": event,
        "tee": "Wasm",
        "mode": "wasm",
        "ms": ms,
    });
    use std::io::Write as _;
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{}", line);
}

fn ms_since(start: std::time::Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// Paper-eval: legacy wasm verifier components may attach per-step timings to
/// their output. Re-emit those as JSON events before stripping the timing keys
/// from returned claims so they never reach the final EAR token.
fn reemit_component_step_timings(result: &Value) {
    let Some(obj) = result.as_object() else {
        return;
    };
    let claims_obj = obj.get("claims").and_then(|v| v.as_object()).or(Some(obj));
    let Some(claims) = claims_obj else {
        return;
    };

    let f = |key: &str| -> Option<f64> { claims.get(key).and_then(|v| v.as_f64()) };
    let cert = f("cert_chain_ms");
    let sig = f("signature_ms");
    let oth = f("others_ms");
    let has_snp_step_timing = cert.is_some() || sig.is_some() || oth.is_some();

    // SNP step breakdown (emitted when SNP_STEP_TIMING_JSON=1 on the host).
    let snp_step_enabled = std::env::var("SNP_STEP_TIMING_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if snp_step_enabled && has_snp_step_timing {
        let cert_v = cert.unwrap_or(0.0);
        let sig_v = sig.unwrap_or(0.0);
        let oth_v = oth.unwrap_or(0.0);
        let line = serde_json::json!({
            "event": "snp_step_timing",
            "mode": std::env::var("SNP_TIMING_MODE").unwrap_or_else(|_| "wasm".to_string()),
            "cert_chain_ms": cert_v,
            "signature_ms": sig_v,
            "others_ms": oth_v,
            "total_ms": cert_v + sig_v + oth_v,
        });
        use std::io::Write as _;
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{}", line);
    }

    // TDX collateral fetch timing. SNP components can also carry timing fields,
    // but must not be re-labeled as TDX collateral events.
    let tdx_coll_enabled = std::env::var("AS_VERIFICATION_TIMING_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if tdx_coll_enabled && !has_snp_step_timing {
        if let Some(ms) = f("collateral_fetch_ms") {
            let tee = claims
                .get(TEE_TYPE_CLAIM)
                .and_then(Value::as_str)
                .map(|tee_type| match tee_type {
                    "sgx" => "Sgx",
                    "tdx" => "Tdx",
                    _ => "Tdx",
                })
                .unwrap_or("Tdx");
            let line = serde_json::json!({
                "event": "as_tdx_collateral_timing",
                "tee": tee,
                "mode": "wasm",
                "ms": ms,
            });
            use std::io::Write as _;
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{}", line);
        }
    }
}

fn add_pccs_url_to_verifier_input(
    mut verifier_input: ComponentVerifierInput,
    pccs_url: Option<&str>,
) -> Result<ComponentVerifierInput> {
    let Some(pccs_url) = pccs_url else {
        return Ok(verifier_input);
    };

    let mut value: Value = match serde_json::from_slice(&verifier_input.evidence) {
        Ok(value) => value,
        Err(_) => return Ok(verifier_input),
    };

    match value {
        Value::Object(ref mut map) => {
            map.insert("pccs_url".to_string(), Value::String(pccs_url.to_string()));
            verifier_input.evidence =
                serde_json::to_vec(&value).context("serialize evidence with pccs_url")?;
            Ok(verifier_input)
        }
        _ => Ok(verifier_input),
    }
}

fn legacy_verifier_input(evidence_bytes: &[u8]) -> ComponentVerifierInput {
    ComponentVerifierInput {
        evidence: evidence_bytes.to_vec(),
        evidence_media_type: infer_legacy_evidence_media_type(evidence_bytes).to_string(),
        endorsements: Vec::new(),
    }
}

fn infer_legacy_evidence_media_type(evidence_bytes: &[u8]) -> &'static str {
    if evidence_bytes
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

fn to_wit_verifier_input(
    verifier_input: ComponentVerifierInput,
) -> exports::trustee::verifier::verifier_interface::VerifierInput {
    let endorsements = verifier_input
        .endorsements
        .into_iter()
        .map(
            |endorsement| exports::trustee::verifier::verifier_interface::Endorsement {
                label: endorsement.label,
                media_type: endorsement.media_type,
                payload: endorsement.payload,
            },
        )
        .collect();

    exports::trustee::verifier::verifier_interface::VerifierInput {
        evidence: verifier_input.evidence,
        evidence_media_type: verifier_input.evidence_media_type,
        endorsements,
    }
}

pub fn verify_evidence(
    component_bytes: &[u8],
    evidence_bytes: &[u8],
    expected_report_data: Option<&[u8]>,
    expected_init_data_hash: Option<&[u8]>,
) -> Result<Value> {
    let verifier = WasmVerificationComponent::new()?;
    verifier.verify_bytes(
        component_bytes,
        evidence_bytes,
        expected_report_data,
        expected_init_data_hash,
        &VerifyOptions::default(),
    )
}

pub fn component_id_for_component_bytes(component_bytes: &[u8]) -> String {
    trustmee_input::component_id_for_bytes(component_bytes)
}

struct HostState {
    table: ResourceTable,
    wasi: wasmtime_wasi::WasiCtx,
    http: wasmtime_wasi_http::WasiHttpCtx,
    network_allowed: bool,
}

impl HostState {
    fn new(cache_dir: &Path, network_allowed: bool) -> Result<Self> {
        let mut wasi = wasmtime_wasi::WasiCtxBuilder::new();
        wasi.inherit_stdio();

        // Paper-eval: forward select env vars into the wasm component so it
        // can emit per-step timing events. Done on an allow-list basis to
        // avoid leaking host env.
        for key in FORWARDED_WASM_ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                wasi.env(key, value);
            }
        }

        use wasmtime_wasi::{DirPerms, FilePerms};
        wasi.preopened_dir(cache_dir, "cache", DirPerms::all(), FilePerms::all())
            .with_context(|| format!("preopen {}", cache_dir.display()))?;

        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
            network_allowed,
        })
    }
}

impl wasmtime_wasi::WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
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

    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::HttpResult<HostFutureIncomingResponse> {
        if !self.network_allowed {
            return Err(WasiHttpErrorCode::HttpRequestDenied.into());
        }

        Ok(default_send_request(request, config))
    }
}

impl trustee::verifier::snp_host_crypto_interface::Host for HostState {
    fn verify_snp_crypto(
        &mut self,
        evidence: Vec<u8>,
        processor: trustee::verifier::snp_host_crypto_interface::ProcessorGeneration,
        vendor_ark_der: Vec<u8>,
        vendor_ask_der: Vec<u8>,
        vendor_asvk_der: Vec<u8>,
        fetched_vcek_der: trustee::verifier::snp_host_crypto_interface::OptionalBytes,
    ) -> std::result::Result<trustee::verifier::snp_host_crypto_interface::VerifiedVekMeta, String>
    {
        let processor = match processor {
            trustee::verifier::snp_host_crypto_interface::ProcessorGeneration::Milan => {
                HostProcessorGeneration::Milan
            }
            trustee::verifier::snp_host_crypto_interface::ProcessorGeneration::Genoa => {
                HostProcessorGeneration::Genoa
            }
            trustee::verifier::snp_host_crypto_interface::ProcessorGeneration::Turin => {
                HostProcessorGeneration::Turin
            }
        };

        let fetched_vcek_der = match fetched_vcek_der {
            trustee::verifier::snp_host_crypto_interface::OptionalBytes::Value(bytes) => {
                Some(bytes)
            }
            trustee::verifier::snp_host_crypto_interface::OptionalBytes::NotProvided => None,
        };

        verify_snp_crypto_host(
            &evidence,
            processor,
            &vendor_ark_der,
            &vendor_ask_der,
            &vendor_asvk_der,
            fetched_vcek_der.as_deref(),
        )
        .map(
            |meta| trustee::verifier::snp_host_crypto_interface::VerifiedVekMeta {
                vek_kind: match meta.vek_kind {
                    HostVekKind::Vcek => {
                        trustee::verifier::snp_host_crypto_interface::VekKind::Vcek
                    }
                    HostVekKind::Vlek => {
                        trustee::verifier::snp_host_crypto_interface::VekKind::Vlek
                    }
                },
                hw_id: match meta.hw_id {
                    Some(bytes) => {
                        trustee::verifier::snp_host_crypto_interface::OptionalBytes::Value(bytes)
                    }
                    None => {
                        trustee::verifier::snp_host_crypto_interface::OptionalBytes::NotProvided
                    }
                },
                bootloader_spl: meta.bootloader_spl,
                tee_spl: meta.tee_spl,
                snp_spl: meta.snp_spl,
                microcode_spl: meta.microcode_spl,
                fmc_spl: meta.fmc_spl,
            },
        )
        .map_err(|err| format!("{err:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_compile_cache_dir, parse_inmem_cache_mode, transform_trustmee_claims, HostState,
        InMemoryCacheMode, VerifyOptions, WasmVerificationComponent, TRUSTMEE_OUTPUT_EAT_PROFILE,
    };
    use serde_json::json;
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use wasmtime_wasi_http::{
        bindings::http::types::ErrorCode as WasiHttpErrorCode, types::OutgoingRequestConfig,
        WasiHttpView,
    };

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{now:x}", std::process::id()))
    }

    #[test]
    fn test_default_compile_cache_dir_is_absolute() {
        let dir = default_compile_cache_dir().expect("resolve compile cache dir");
        assert!(dir.is_absolute());
    }

    #[test]
    fn test_verify_options_default_leaves_component_trust_store_unset() {
        let options = VerifyOptions::default();
        assert!(options.component_trust_store.is_none());
    }

    #[test]
    fn test_load_component_reuses_cached_instance_pre() {
        let verifier = WasmVerificationComponent::new().expect("create verifier");
        let component_path = project_root().join("test_data/snp_verifier_component.wasm");
        let component_bytes = std::fs::read(&component_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", component_path.display()));

        let first = verifier
            .load_component(&component_bytes)
            .expect("load component first time");
        let second = verifier
            .load_component(&component_bytes)
            .expect("load component second time");

        assert!(Arc::ptr_eq(&first.inner, &second.inner));
    }

    #[test]
    fn test_load_component_accepts_snp_host_crypto_component() {
        let verifier = WasmVerificationComponent::new().expect("create verifier");
        let component_path =
            project_root().join("test_data/snp_verifier_host_crypto_component.wasm");
        let component_bytes = std::fs::read(&component_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", component_path.display()));

        verifier
            .load_component(&component_bytes)
            .expect("load host crypto SNP component");
    }

    #[test]
    fn test_parse_inmem_cache_mode_defaults_to_warm() {
        assert_eq!(parse_inmem_cache_mode(None), Some(InMemoryCacheMode::Warm));
        assert_eq!(
            parse_inmem_cache_mode(Some("")),
            Some(InMemoryCacheMode::Warm)
        );
        assert_eq!(
            parse_inmem_cache_mode(Some("preinstantiate")),
            Some(InMemoryCacheMode::Warm)
        );
    }

    #[test]
    fn test_parse_inmem_cache_mode_accepts_hot_and_cold() {
        assert_eq!(
            parse_inmem_cache_mode(Some("hot")),
            Some(InMemoryCacheMode::Hot)
        );
        assert_eq!(
            parse_inmem_cache_mode(Some("instantiated")),
            Some(InMemoryCacheMode::Hot)
        );
        assert_eq!(
            parse_inmem_cache_mode(Some("cold")),
            Some(InMemoryCacheMode::Disabled)
        );
    }

    #[test]
    fn test_parse_inmem_cache_mode_rejects_unknown_values() {
        assert_eq!(parse_inmem_cache_mode(Some("surprise")), None);
    }

    #[test]
    fn test_transform_trustmee_claims() {
        let transformed = transform_trustmee_claims(json!({
            "tee_type": "snp",
            "report_data": "abcdef",
            "init_data": "fedcba",
            "measurement": "012345",
            "reported_tcb_snp": 23,
            "collateral_fetch_ms": 1.25,
            "wasm_verify_ms": 2.5,
            "cert_chain_ms": 3.75,
            "signature_ms": 4.0,
            "others_ms": 5.5,
            "total_ms": 13.25,
            "verifier_component_sha256": "deadbeef",
            "verifier_component_signature_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
        }))
        .expect("transform trustmee claims");

        assert_eq!(
            transformed,
            json!({
                "eat_profile": TRUSTMEE_OUTPUT_EAT_PROFILE,
                "report_data": "abcdef",
                "init_data": "fedcba",
                "tee_type": "snp",
                "claims": {
                    "measurement": "012345",
                    "reported_tcb_snp": 23
                },
                "verifier_component_sha256": "deadbeef",
                "verifier_component_signature_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
            })
        );
    }

    #[test]
    fn test_transform_trustmee_claims_requires_tee_type() {
        let err = transform_trustmee_claims(json!({
            "measurement": "012345",
            "verifier_component_sha256": "deadbeef"
        }))
        .expect_err("tee_type should be required");

        assert!(
            format!("{err:#}").contains("tee_type"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_host_state_denies_network_when_disabled() {
        let cache_dir = unique_temp_dir("trustmee-host-state-cache");
        std::fs::create_dir_all(&cache_dir)
            .unwrap_or_else(|e| panic!("create {}: {e}", cache_dir.display()));
        let mut state = HostState::new(&cache_dir, false).expect("create host state");
        let request = hyper::Request::builder()
            .uri("https://example.com/")
            .body(wasmtime_wasi_http::body::HyperOutgoingBody::default())
            .expect("build request");

        let err = <HostState as WasiHttpView>::send_request(
            &mut state,
            request,
            OutgoingRequestConfig {
                use_tls: true,
                connect_timeout: Duration::from_secs(1),
                first_byte_timeout: Duration::from_secs(1),
                between_bytes_timeout: Duration::from_secs(1),
            },
        )
        .expect_err("network should be denied");

        let err_code = err.downcast().expect("downcast to wasi-http error code");
        assert!(matches!(err_code, WasiHttpErrorCode::HttpRequestDenied));
    }
}
