use crate::ear_token::EarTokenConfiguration;
use crate::rvps::RvpsConfig;

use verifier::VerifierConfig;

use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Environment macro for Attestation Service work dir.
const AS_WORK_DIR: &str = "AS_WORK_DIR";
pub const DEFAULT_WORK_DIR: &str = "/opt/confidential-containers/attestation-service";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    /// The location for Attestation Service to store data.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// Configurations for RVPS.
    #[serde(default)]
    pub rvps_config: RvpsConfig,

    /// The Attestation Result Token Broker Config
    #[serde(default)]
    pub attestation_token_broker: EarTokenConfiguration,

    /// Optional configuration for verifier modules
    #[serde(default)]
    pub verifier_config: Option<VerifierConfig>,

    /// Configuration for hosting Wasm component verifiers.
    #[serde(default)]
    pub wasm_verifier: WasmVerifierConfig,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct WasmVerifierConfig {
    /// Enable loading and invoking Wasm component verifiers.
    #[serde(default)]
    pub enabled: bool,

    /// If `false`, Wasm components must carry a valid `wasmsign2` signature that
    /// matches one of the `trusted_public_keys`.
    #[serde(default)]
    pub allow_unsigned: bool,

    /// Trusted public keys used to validate uploaded Wasm components.
    /// Keys can be in `wasmsign2` raw format, DER, PEM, or OpenSSH public key format.
    #[serde(default)]
    pub trusted_public_keys: Vec<PathBuf>,

    /// Optional directory for storing registered components. When unset,
    /// defaults to `<work_dir>/components`.
    #[serde(default)]
    pub registry_dir: Option<PathBuf>,

    /// Optional default component ID to use when a request does not include
    /// `verifier_component` (inline) or `verifier_component_id` (cache reference).
    ///
    /// This enables gRPC/KBS callers (or legacy clients) to keep sending only
    /// evidence while the AS fetches the verifier component from its registry.
    #[serde(default)]
    pub default_component_id: Option<String>,

    /// Optional directory pre-opened to Wasm components as `cache/` for
    /// collateral caching. When unset, defaults to `<work_dir>/wasm-cache`.
    #[serde(default)]
    pub wasi_cache_dir: Option<PathBuf>,

    /// Optional Wasmtime cache config file path. When unset, defaults to
    /// `<work_dir>/wasmtime-cache.toml` (created automatically) and stores cache
    /// artifacts under `<work_dir>/wasmtime-cache/`.
    #[serde(default)]
    pub wasmtime_cache_config: Option<PathBuf>,
}

impl Default for WasmVerifierConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_unsigned: false,
            trusted_public_keys: vec![],
            registry_dir: None,
            default_component_id: None,
            wasi_cache_dir: None,
            wasmtime_cache_config: None,
        }
    }
}

fn default_work_dir() -> PathBuf {
    PathBuf::from(std::env::var(AS_WORK_DIR).unwrap_or_else(|_| DEFAULT_WORK_DIR.to_string()))
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to parse AS config file: {0}")]
    FileParse(#[source] std::io::Error),
    #[error("failed to parse AS config file: {0}")]
    JsonFileParse(#[source] serde_json::Error),
    #[error("Illegal format of the content of the configuration file: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            work_dir: default_work_dir(),
            rvps_config: RvpsConfig::default(),
            attestation_token_broker: EarTokenConfiguration::default(),
            verifier_config: None,
            wasm_verifier: WasmVerifierConfig::default(),
        }
    }
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/attestation-service/",
    ///        "policy_engine": "opa",
    ///        "rvps_config": {
    ///            "storage": {
    ///                "type": "LocalFs"
    ///            }
    ///            "store_config": {},
    ///        },
    ///        "attestation_token_broker": {
    ///            "duration_min": 5
    ///        },
    ///        "verifier_config": {
    ///            "tpm_verifier": {
    ///                "trusted_ak_keys_dir": "/etc/tpm/trusted_ak_keys",
    ///                "max_trusted_ak_keys": 100
    ///            }
    ///        }
    ///    }
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, Config>(file).map_err(ConfigError::JsonFileParse)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::path::PathBuf;

    use super::Config;
    use crate::ear_token::TokenSignerConfig;
    use crate::rvps::RvpsCrateConfig;
    use crate::{ear_token::EarTokenConfiguration, rvps::RvpsConfig};
    use reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig};

    #[rstest]
    #[case("./tests/configs/example1.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
            extractors: None,
        }),
        attestation_token_broker: EarTokenConfiguration {
            duration_min: 5,
            issuer_name: "test".into(),
            signer: None,
            policy_dir: "/var/lib/attestation-service/policies".into(),
            developer_name: "someone".into(),
            build_name: "0.1.0".into(),
            profile_name: "tag:github.com,2024:confidential-containers/Trustee".into()
        },
        verifier_config: None,
        wasm_verifier: crate::config::WasmVerifierConfig::default(),
    })]
    #[case("./tests/configs/example2.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
            extractors: None,
        }),
        attestation_token_broker: EarTokenConfiguration {
            duration_min: 5,
            issuer_name: "test".into(),
            policy_dir: "/var/lib/attestation-service/policies".into(),
            developer_name: "someone".into(),
            build_name: "0.1.0".into(),
            profile_name: "tag:github.com,2024:confidential-containers/Trustee".into(),
            signer: Some(TokenSignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into())
            })
        },
        verifier_config: None,
        wasm_verifier: crate::config::WasmVerifierConfig::default(),
    })]
    fn read_config(#[case] config: &str, #[case] expected: Config) {
        let config = std::fs::read_to_string(config).unwrap();
        let config: Config = serde_json::from_str(&config).unwrap();
        assert_eq!(config, expected);
    }
}
