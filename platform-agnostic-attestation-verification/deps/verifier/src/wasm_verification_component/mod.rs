use std::{
    path::PathBuf,
    sync::{Arc, OnceLock, RwLock},
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

use crate::{InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};

#[derive(Clone, Debug)]
pub struct ComponentRegistryConfig {
    pub component_trust_store: Option<PathBuf>,
    pub component_cache_base_dir: PathBuf,
}

impl Default for ComponentRegistryConfig {
    fn default() -> Self {
        Self {
            component_trust_store: None,
            component_cache_base_dir: default_component_cache_base_dir(),
        }
    }
}

fn default_tee_class() -> String {
    "cpu".to_string()
}

fn default_component_cache_base_dir() -> PathBuf {
    PathBuf::from(".wasm-verification-component-cache/components")
}

static WASM_VERIFIER: OnceLock<Result<Arc<WasmVerificationComponent>, String>> = OnceLock::new();
static DRIVER_CONFIG: OnceLock<RwLock<ComponentRegistryConfig>> = OnceLock::new();

fn verifier_instance() -> Result<Arc<WasmVerificationComponent>> {
    let verifier = WASM_VERIFIER.get_or_init(|| {
        WasmVerificationComponent::new()
            .map(Arc::new)
            .map_err(|e| format!("{e:#}"))
    });
    match verifier {
        Ok(verifier) => Ok(Arc::clone(verifier)),
        Err(err) => bail!("initialize wasm-verification-component verifier: {err}"),
    }
}

fn driver_config() -> &'static RwLock<ComponentRegistryConfig> {
    DRIVER_CONFIG.get_or_init(|| RwLock::new(ComponentRegistryConfig::default()))
}

pub fn configure_component_registry(config: ComponentRegistryConfig) -> Result<()> {
    std::fs::create_dir_all(&config.component_cache_base_dir)
        .with_context(|| format!("create {}", config.component_cache_base_dir.display()))?;

    let driver_config = driver_config();
    let mut driver_config = driver_config
        .write()
        .map_err(|_| anyhow!("wasm-verification-component config lock poisoned"))?;
    *driver_config = config;
    Ok(())
}

fn current_driver_config() -> Result<ComponentRegistryConfig> {
    let driver_config = driver_config();
    let driver_config = driver_config
        .read()
        .map_err(|_| anyhow!("wasm-verification-component config lock poisoned"))?;
    Ok(driver_config.clone())
}

fn verify_options_from_config(config: &ComponentRegistryConfig) -> VerifyOptions {
    VerifyOptions {
        cache_dir: config.component_cache_base_dir.clone(),
        pccs_url: None,
        component_repository_hint: None,
        component_trust_store: config.component_trust_store.clone(),
    }
}

fn cmw_from_evidence(evidence: TeeEvidence) -> Result<Vec<u8>> {
    let encoded = evidence.as_str().ok_or_else(|| {
        anyhow!(
            "for verifier `wasm-verification-component`, evidence must be a URL-safe base64 string carrying raw TrustMee CMW bytes"
        )
    })?;

    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("base64 decode TrustMee CMW bytes")
}

pub struct WasmVerificationComponentDriver;

impl WasmVerificationComponentDriver {
    pub fn new() -> Result<Self> {
        let config = current_driver_config()?;
        std::fs::create_dir_all(&config.component_cache_base_dir)
            .with_context(|| format!("create {}", config.component_cache_base_dir.display()))?;
        let _ = verifier_instance()?;
        Ok(Self)
    }
}

#[async_trait]
impl Verifier for WasmVerificationComponentDriver {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let cmw_bytes = cmw_from_evidence(evidence)?;
        let config = current_driver_config()?;
        let verifier = verifier_instance()?;
        let options = verify_options_from_config(&config);

        let expected_report_data = match expected_report_data {
            ReportData::Value(data) => Some(data.to_vec()),
            ReportData::NotProvided => None,
        };

        let expected_init_data_hash = match expected_init_data_hash {
            InitDataHash::Value(data) => Some(data.to_vec()),
            InitDataHash::NotProvided => None,
        };

        let claims = std::thread::spawn(move || {
            verifier.verify_cmw_bytes(
                &cmw_bytes,
                expected_report_data.as_deref(),
                expected_init_data_hash.as_deref(),
                &options,
            )
        })
        .join()
        .map_err(|_| anyhow!("wasm-verification-component evaluate thread panicked"))?
        .map_err(|e| anyhow!("wasm-verification-component evaluate failed: {e:#}"))?;

        Ok(vec![(claims, default_tee_class())])
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cmw_from_evidence, default_component_cache_base_dir, default_tee_class,
        verify_options_from_config, ComponentRegistryConfig,
    };
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn test_default_tee_class() {
        assert_eq!(default_tee_class(), "cpu");
    }

    #[test]
    fn test_default_component_cache_base_dir() {
        assert_eq!(
            default_component_cache_base_dir().to_string_lossy(),
            ".wasm-verification-component-cache/components"
        );
    }

    #[test]
    fn test_registry_config_defaults_trust_store_to_none() {
        let cfg = ComponentRegistryConfig::default();
        assert!(cfg.component_trust_store.is_none());
    }

    #[test]
    fn test_verify_options_from_config_passes_component_trust_store() {
        let cfg = ComponentRegistryConfig {
            component_trust_store: Some(PathBuf::from("/etc/trustmee/component-trust-store.json")),
            component_cache_base_dir: PathBuf::from("/var/cache/trustmee-components"),
        };

        let options = verify_options_from_config(&cfg);

        assert_eq!(options.cache_dir, cfg.component_cache_base_dir);
        assert_eq!(options.component_trust_store, cfg.component_trust_store);
        assert_eq!(options.pccs_url, None);
        assert_eq!(options.component_repository_hint, None);
    }

    #[test]
    fn test_cmw_from_evidence_accepts_base64url_string() {
        let decoded = cmw_from_evidence(json!("Zm9v")).expect("decode TrustMee CMW evidence");
        assert_eq!(decoded, b"foo");
    }

    #[test]
    fn test_cmw_from_evidence_rejects_non_string() {
        let err = cmw_from_evidence(json!({"cmw": "Zm9v"}))
            .expect_err("non-string TrustMee evidence must fail");
        assert!(
            format!("{err:#}").contains("URL-safe base64 string"),
            "unexpected error: {err:#}"
        );
    }
}
