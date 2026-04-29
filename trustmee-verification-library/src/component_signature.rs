use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::DateTime;
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wasmsign2::{signature_info_from_reader, PublicKey, PublicKeySet, WSError};

pub(crate) const DEFAULT_UNSIGNED_COMPONENT_FUEL: u64 = 1_000_000_000;
const UNLIMITED_FUEL_SENTINEL: i64 = -1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionPolicy {
    pub(crate) fuel: u64,
    pub(crate) network_allowed: bool,
}

impl ExecutionPolicy {
    pub(crate) fn legacy_unrestricted() -> Self {
        Self {
            fuel: u64::MAX,
            network_allowed: true,
        }
    }

    pub(crate) fn unsigned_default() -> Self {
        // Paper-eval: the unsigned default disables WASI networking. Eval 7
        // needs the wasm verifier to hit KDS / Intel PCS, so we expose an
        // env-var override so the evaluation host can re-enable it without
        // shipping a signed component + trust store.
        let network_allowed = std::env::var("TRUSTMEE_ALLOW_UNSIGNED_NETWORK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            fuel: DEFAULT_UNSIGNED_COMPONENT_FUEL,
            network_allowed,
        }
    }
}

#[derive(Debug)]
struct TrustedSigner {
    public_key: PublicKey,
    public_key_id_hex: String,
    fuel: u64,
    network_allowed: bool,
    valid_until: SystemTime,
}

#[derive(Debug)]
struct TrustStore {
    signers: Vec<TrustedSigner>,
}

#[derive(Debug, Deserialize)]
struct TrustStoreFile {
    #[serde(default)]
    signers: Vec<TrustStoreEntryFile>,
}

#[derive(Debug, Deserialize)]
struct TrustStoreEntryFile {
    public_key: String,
    fuel: i64,
    allow_network: bool,
    valid_until: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComponentSignatureState {
    Unsigned,
    Signed,
}

pub(crate) fn resolve_execution_policy_for_cmw(
    component_bytes: &[u8],
    trust_store_path: Option<&Path>,
    now: SystemTime,
) -> Result<ExecutionPolicy> {
    match component_signature_state(component_bytes)? {
        ComponentSignatureState::Unsigned => Ok(ExecutionPolicy::unsigned_default()),
        ComponentSignatureState::Signed => {
            let trust_store_path = trust_store_path.ok_or_else(|| {
                anyhow!("component signature present but no component trust store was configured")
            })?;
            let trust_store = TrustStore::from_file(trust_store_path)?;
            trust_store.resolve_signed_execution_policy(component_bytes, now)
        }
    }
}

pub(crate) fn resolve_execution_policy_for_direct(
    component_bytes: &[u8],
    trust_store_path: Option<&Path>,
    now: SystemTime,
) -> Result<ExecutionPolicy> {
    let Some(trust_store_path) = trust_store_path else {
        return Ok(ExecutionPolicy::legacy_unrestricted());
    };

    match component_signature_state(component_bytes)? {
        ComponentSignatureState::Unsigned => Ok(ExecutionPolicy::unsigned_default()),
        ComponentSignatureState::Signed => {
            let trust_store = TrustStore::from_file(trust_store_path)?;
            trust_store.resolve_signed_execution_policy(component_bytes, now)
        }
    }
}

fn component_signature_state(component_bytes: &[u8]) -> Result<ComponentSignatureState> {
    match signature_info_from_reader(&mut &component_bytes[..], None) {
        Ok(_) => Ok(ComponentSignatureState::Signed),
        Err(WSError::NoSignatures) => Ok(ComponentSignatureState::Unsigned),
        Err(WSError::UnsupportedModuleType) => bail!(
            "wasmsign2 does not support the component binary format used by this verifier component"
        ),
        Err(err) => Err(err).context("inspect embedded component signature"),
    }
}

impl TrustStore {
    fn from_file(path: &Path) -> Result<Self> {
        let contents =
            fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_json_str(&contents)
            .with_context(|| format!("parse component trust store at {}", path.display()))
    }

    fn from_json_str(contents: &str) -> Result<Self> {
        let file: TrustStoreFile =
            serde_json::from_str(contents).context("deserialize trust store JSON")?;

        let mut signers = Vec::with_capacity(file.signers.len());
        let mut seen_public_keys = HashSet::new();
        for (idx, signer) in file.signers.into_iter().enumerate() {
            let public_key = parse_public_key_field(&signer.public_key)
                .with_context(|| format!("parse `signers[{idx}].public_key`"))?
                .attach_default_key_id();
            if !seen_public_keys.insert(public_key.clone()) {
                bail!("duplicate public key in trust store at `signers[{idx}]`");
            }

            let fuel =
                parse_fuel(signer.fuel).with_context(|| format!("parse `signers[{idx}].fuel`"))?;
            let valid_until = parse_valid_until(&signer.valid_until)
                .with_context(|| format!("parse `signers[{idx}].valid_until`"))?;
            let public_key_id_hex = public_key
                .key_id()
                .map(hex::encode)
                .ok_or_else(|| anyhow!("missing computed key id for `signers[{idx}]`"))?;

            signers.push(TrustedSigner {
                public_key,
                public_key_id_hex,
                fuel,
                network_allowed: signer.allow_network,
                valid_until,
            });
        }

        Ok(Self { signers })
    }

    fn resolve_signed_execution_policy(
        &self,
        component_bytes: &[u8],
        now: SystemTime,
    ) -> Result<ExecutionPolicy> {
        let matching_signers = self
            .matching_signers(component_bytes)
            .context("verify embedded component signature against trust store")?;

        if matching_signers.is_empty() {
            bail!("component signature did not verify against any trusted public key");
        }

        let unexpired_signers: Vec<&TrustedSigner> = matching_signers
            .iter()
            .copied()
            .filter(|signer| now <= signer.valid_until)
            .collect();

        if unexpired_signers.is_empty() {
            let signer_ids = matching_signers
                .iter()
                .map(|signer| signer.public_key_id_hex.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("component signature matched only expired trusted public key(s): {signer_ids}");
        }

        if unexpired_signers.len() > 1 {
            let signer_ids = unexpired_signers
                .iter()
                .map(|signer| signer.public_key_id_hex.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("component signature matched multiple trusted public keys: {signer_ids}");
        }

        let signer = unexpired_signers[0];
        Ok(ExecutionPolicy {
            fuel: signer.fuel,
            network_allowed: signer.network_allowed,
        })
    }

    fn matching_signers<'a>(&'a self, component_bytes: &[u8]) -> Result<Vec<&'a TrustedSigner>> {
        let key_set = PublicKeySet::new(
            self.signers
                .iter()
                .map(|signer| signer.public_key.clone())
                .collect(),
        );

        let valid_public_keys = match key_set.verify(&mut &component_bytes[..], None) {
            Ok(keys) => keys,
            Err(WSError::VerificationFailed) => return Ok(Vec::new()),
            Err(WSError::NoSignatures) => {
                bail!("component does not contain an embedded signature")
            }
            Err(WSError::UnsupportedModuleType) => bail!(
                "wasmsign2 does not support the component binary format used by this verifier component"
            ),
            Err(err) => return Err(err).context("verify component signature"),
        };

        Ok(self
            .signers
            .iter()
            .filter(|signer| valid_public_keys.contains(&&signer.public_key))
            .collect())
    }
}

fn parse_fuel(raw_fuel: i64) -> Result<u64> {
    match raw_fuel {
        UNLIMITED_FUEL_SENTINEL => Ok(u64::MAX),
        value if value >= 0 => Ok(value as u64),
        _ => bail!("fuel must be -1 or a non-negative integer"),
    }
}

fn parse_valid_until(raw_valid_until: &str) -> Result<SystemTime> {
    let timestamp = DateTime::parse_from_rfc3339(raw_valid_until)
        .context("expected RFC3339 timestamp")?
        .timestamp_nanos_opt()
        .ok_or_else(|| anyhow!("RFC3339 timestamp is out of range"))?;

    if timestamp < 0 {
        bail!("valid_until must not be earlier than the Unix epoch");
    }

    Ok(UNIX_EPOCH + Duration::from_nanos(timestamp as u64))
}

fn parse_public_key_field(raw_public_key: &str) -> Result<PublicKey> {
    if let Ok(public_key) = PublicKey::from_any(raw_public_key.as_bytes()) {
        return Ok(public_key);
    }

    if raw_public_key.len() % 2 == 0 && raw_public_key.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        let decoded = hex::decode(raw_public_key).context("decode hex-encoded public key")?;
        if let Ok(public_key) = PublicKey::from_any(&decoded) {
            return Ok(public_key);
        }
    }

    for decoded in decode_base64_variants(raw_public_key) {
        if let Ok(public_key) = PublicKey::from_any(&decoded) {
            return Ok(public_key);
        }
    }

    bail!(
        "unsupported public_key encoding; expected PEM/OpenSSH text or raw key bytes encoded as hex/base64/base64url"
    )
}

fn decode_base64_variants(value: &str) -> Vec<Vec<u8>> {
    let mut decoded_variants = Vec::new();
    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(decoded) = engine.decode(value) {
            decoded_variants.push(decoded);
        }
    }
    decoded_variants
}

#[cfg(test)]
mod tests {
    use super::{
        parse_fuel, parse_valid_until, resolve_execution_policy_for_cmw,
        resolve_execution_policy_for_direct, ExecutionPolicy, DEFAULT_UNSIGNED_COMPONENT_FUEL,
    };
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use wasmsign2::{KeyPair, Module};

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn sample_component_bytes() -> Vec<u8> {
        let path = project_root().join("test_data/snp_verifier_component.wasm");
        fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn signed_component_and_public_key() -> (Vec<u8>, wasmsign2::PublicKey) {
        let component_bytes = sample_component_bytes();
        let key_pair = KeyPair::generate();
        let public_key = key_pair.pk.clone().attach_default_key_id();
        let key_id = public_key
            .key_id()
            .expect("attached default key id")
            .clone();
        let module =
            Module::deserialize(&mut &component_bytes[..]).expect("parse component for signing");
        let signed_module = key_pair
            .sk
            .sign(module, Some(&key_id))
            .expect("sign component bytes");
        let mut signed_bytes = Vec::new();
        signed_module
            .serialize(&mut signed_bytes)
            .expect("serialize signed component");
        (signed_bytes, public_key)
    }

    fn unique_test_file(prefix: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{now:x}.json", std::process::id()))
    }

    fn trust_store_file(
        public_keys: &[String],
        fuel: i64,
        allow_network: bool,
        valid_until: &str,
    ) -> PathBuf {
        let path = unique_test_file("trustmee-component-trust-store");
        let signers = public_keys
            .iter()
            .map(|public_key| {
                serde_json::json!({
                    "public_key": public_key,
                    "fuel": fuel,
                    "allow_network": allow_network,
                    "valid_until": valid_until,
                })
            })
            .collect::<Vec<_>>();
        let json = serde_json::json!({ "signers": signers });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&json).expect("serialize trust store"),
        )
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        path
    }

    #[test]
    fn parse_fuel_supports_unlimited_sentinel() {
        assert_eq!(parse_fuel(-1).expect("parse unlimited fuel"), u64::MAX);
        assert_eq!(parse_fuel(123).expect("parse finite fuel"), 123);
        assert!(parse_fuel(-2).is_err());
    }

    #[test]
    fn parse_valid_until_accepts_rfc3339() {
        let parsed =
            parse_valid_until("2026-12-31T23:59:59Z").expect("parse valid_until timestamp");
        assert!(parsed > UNIX_EPOCH);
    }

    #[test]
    fn wasmsign2_can_sign_and_verify_component_model_binaries() {
        let (signed_component_bytes, public_key) = signed_component_and_public_key();
        public_key
            .verify(&mut &signed_component_bytes[..], None)
            .expect("verify signed component bytes");
    }

    #[test]
    fn resolve_execution_policy_for_direct_without_trust_store_is_legacy() {
        let component_bytes = sample_component_bytes();
        let policy = resolve_execution_policy_for_direct(
            &component_bytes,
            None,
            UNIX_EPOCH + Duration::from_secs(1),
        )
        .expect("resolve legacy direct policy");
        assert_eq!(policy, ExecutionPolicy::legacy_unrestricted());
    }

    #[test]
    fn resolve_execution_policy_for_unsigned_component_defaults_to_restricted() {
        let component_bytes = sample_component_bytes();
        let policy = resolve_execution_policy_for_cmw(
            &component_bytes,
            None,
            UNIX_EPOCH + Duration::from_secs(1),
        )
        .expect("resolve unsigned component policy");
        assert_eq!(
            policy,
            ExecutionPolicy {
                fuel: DEFAULT_UNSIGNED_COMPONENT_FUEL,
                network_allowed: false,
            }
        );
    }

    #[test]
    fn resolve_execution_policy_for_signed_component_requires_trust_store() {
        let (signed_component_bytes, _public_key) = signed_component_and_public_key();
        let err = resolve_execution_policy_for_cmw(
            &signed_component_bytes,
            None,
            UNIX_EPOCH + Duration::from_secs(1),
        )
        .expect_err("signed component without trust store must fail");
        assert!(
            format!("{err:#}").contains("no component trust store"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn resolve_execution_policy_for_signed_component_uses_trusted_signer_policy() {
        let (signed_component_bytes, public_key) = signed_component_and_public_key();
        let trust_store =
            trust_store_file(&[public_key.to_pem()], 1234, true, "2030-01-01T00:00:00Z");

        let policy = resolve_execution_policy_for_cmw(
            &signed_component_bytes,
            Some(&trust_store),
            UNIX_EPOCH + Duration::from_secs(1),
        )
        .expect("resolve trusted signer policy");
        assert_eq!(
            policy,
            ExecutionPolicy {
                fuel: 1234,
                network_allowed: true,
            }
        );
    }

    #[test]
    fn resolve_execution_policy_for_signed_component_rejects_untrusted_signer() {
        let (signed_component_bytes, _public_key) = signed_component_and_public_key();
        let other_key = KeyPair::generate().pk.attach_default_key_id();
        let trust_store =
            trust_store_file(&[other_key.to_pem()], 1234, true, "2030-01-01T00:00:00Z");

        let err = resolve_execution_policy_for_cmw(
            &signed_component_bytes,
            Some(&trust_store),
            UNIX_EPOCH + Duration::from_secs(1),
        )
        .expect_err("untrusted signer must fail");
        assert!(
            format!("{err:#}").contains("did not verify against any trusted public key"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn resolve_execution_policy_for_signed_component_rejects_expired_signer() {
        let (signed_component_bytes, public_key) = signed_component_and_public_key();
        let trust_store =
            trust_store_file(&[public_key.to_pem()], 1234, true, "1970-01-01T00:00:01Z");

        let err = resolve_execution_policy_for_cmw(
            &signed_component_bytes,
            Some(&trust_store),
            UNIX_EPOCH + Duration::from_secs(2),
        )
        .expect_err("expired signer must fail");
        assert!(
            format!("{err:#}").contains("expired trusted public key"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn resolve_execution_policy_for_signed_component_rejects_multiple_matching_signers() {
        let (signed_component_bytes, public_key) = signed_component_and_public_key();
        let same_key_twice = vec![public_key.to_pem(), public_key.to_pem()];
        let trust_store = trust_store_file(&same_key_twice, 1234, true, "2030-01-01T00:00:00Z");

        let err = resolve_execution_policy_for_cmw(
            &signed_component_bytes,
            Some(&trust_store),
            UNIX_EPOCH + Duration::from_secs(1),
        )
        .expect_err("duplicate trusted signer entries must fail");
        assert!(
            format!("{err:#}").contains("duplicate public key"),
            "unexpected error: {err:#}"
        );
    }
}
