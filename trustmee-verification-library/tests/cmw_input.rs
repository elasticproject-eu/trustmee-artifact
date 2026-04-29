use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::into_writer;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sev::{
    firmware::{guest::AttestationReport, host::CertTableEntry},
    parser::ByteParser,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    future::Future,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use wasm_pkg_client::{
    Client as WasmPkgClient, Config as WasmPkgConfig, PackageRef as WasmPkgPackageRef,
    PublishOpts as WasmPkgPublishOpts, Version as WasmPkgVersion,
};
use wasm_verification_component::{
    component_id_for_component_bytes, VerifyOptions, WasmVerificationComponent,
    SNP_COLLATERAL_MEDIA_TYPE, TRUSTMEE_COLLECTION_TYPE, TRUSTMEE_EAT_PROFILE,
    TRUSTMEE_OUTPUT_EAT_PROFILE,
};
use wasmsign2::{KeyPair, Module, PublicKey};

const CMW_INDICATOR_ENDORSEMENT: u64 = 1 << 1;
const CMW_INDICATOR_EVIDENCE: u64 = 1 << 2;

#[derive(Debug, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

#[derive(Debug, Serialize)]
struct SnpCollateral {
    cert_chain: Vec<CertTableEntry>,
}

#[derive(Debug, Serialize)]
struct CborEatClaims {
    eat_profile: String,
    component_id: String,
    evidence: Vec<u8>,
    evidence_type: String,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn test_data_component_path(name: &str) -> PathBuf {
    project_root().join("test_data").join(name)
}

fn host_crypto_component_bytes() -> Vec<u8> {
    let path = test_data_component_path("snp_verifier_host_crypto_component.wasm");
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn plain_snp_component_bytes() -> Vec<u8> {
    let path = test_data_component_path("snp_verifier_component.wasm");
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn tdx_component_bytes() -> Vec<u8> {
    let path = test_data_component_path("tdx_verifier_component.wasm");
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn snp_report_and_collateral() -> (Vec<u8>, Vec<u8>) {
    let path = project_root().join("test_data/snp_evidence.json");
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let parsed: SnpEvidence =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    let cert_chain = parsed
        .cert_chain
        .clone()
        .expect("sample SNP evidence includes cert_chain");
    let report_bytes = parsed
        .attestation_report
        .to_bytes()
        .expect("encode attestation report")
        .to_vec();

    let collateral = SnpCollateral { cert_chain };
    let mut collateral_bytes = Vec::new();
    into_writer(&collateral, &mut collateral_bytes).expect("encode SNP collateral");

    (report_bytes, collateral_bytes)
}

fn tdx_quote_bytes() -> Vec<u8> {
    let path = project_root().join("test_data/tdx_quote.bin");
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn default_options() -> VerifyOptions {
    VerifyOptions {
        cache_dir: unique_test_dir("trustmee-cmw-cache-default"),
        pccs_url: None,
        component_repository_hint: None,
        component_trust_store: None,
    }
}

fn sample_plain_snp_component_bytes() -> Vec<u8> {
    let path = project_root().join("test_data/snp_verifier_component.wasm");
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn sample_snp_evidence_json_bytes() -> Vec<u8> {
    let path = project_root().join("test_data/snp_evidence.json");
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn sign_component_bytes(component_bytes: &[u8]) -> (Vec<u8>, PublicKey) {
    let key_pair = KeyPair::generate();
    let public_key = key_pair.pk.clone().attach_default_key_id();
    let key_id = public_key
        .key_id()
        .expect("attached default key id")
        .clone();
    let module = Module::deserialize(&mut &component_bytes[..])
        .expect("parse verifier component as signable wasm payload");
    let signed_module = key_pair
        .sk
        .sign(module, Some(&key_id))
        .expect("sign verifier component");
    let mut signed_component_bytes = Vec::new();
    signed_module
        .serialize(&mut signed_component_bytes)
        .expect("serialize signed component");
    (signed_component_bytes, public_key)
}

fn multi_sign_component_bytes(component_bytes: &[u8]) -> (Vec<u8>, Vec<PublicKey>) {
    let first_key_pair = KeyPair::generate();
    let first_public_key = first_key_pair.pk.clone().attach_default_key_id();
    let first_key_id = first_public_key
        .key_id()
        .expect("attached default key id")
        .clone();

    let second_key_pair = KeyPair::generate();
    let second_public_key = second_key_pair.pk.clone().attach_default_key_id();
    let second_key_id = second_public_key
        .key_id()
        .expect("attached default key id")
        .clone();

    let module = Module::deserialize(&mut &component_bytes[..])
        .expect("parse verifier component as signable wasm payload");
    let (first_signed_module, _) = first_key_pair
        .sk
        .sign_multi(module, Some(&first_key_id), false, false)
        .expect("sign verifier component with first key");
    let (multi_signed_module, _) = second_key_pair
        .sk
        .sign_multi(first_signed_module, Some(&second_key_id), false, false)
        .expect("sign verifier component with second key");

    let mut signed_component_bytes = Vec::new();
    multi_signed_module
        .serialize(&mut signed_component_bytes)
        .expect("serialize multi-signed component");
    (
        signed_component_bytes,
        vec![first_public_key, second_public_key],
    )
}

fn assert_component_hash(result: &serde_json::Value, component_bytes: &[u8]) {
    let expected_hash = hex::encode(Sha256::digest(component_bytes));
    assert_eq!(
        result["verifier_component_sha256"].as_str(),
        Some(expected_hash.as_str())
    );
}

fn assert_tee_type(result: &serde_json::Value, expected: &str) {
    assert_eq!(result["tee_type"].as_str(), Some(expected));
}

fn assert_output_eat_profile(result: &serde_json::Value) {
    assert_eq!(
        result["eat_profile"].as_str(),
        Some(TRUSTMEE_OUTPUT_EAT_PROFILE)
    );
}

fn claims(result: &serde_json::Value) -> &serde_json::Value {
    &result["claims"]
}

fn assert_snp_basic_claims(result: &serde_json::Value) {
    assert_output_eat_profile(result);
    assert_eq!(claims(result)["reported_tcb_snp"], 23);
    assert_eq!(claims(result)["reported_tcb_bootloader"], 10);
    assert!(
        result["report_data"]
            .as_str()
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "report_data should stay at the top level"
    );
    assert!(
        result["init_data"]
            .as_str()
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "init_data should stay at the top level"
    );
    assert!(claims(result).get("report_data").is_none());
    assert!(claims(result).get("init_data").is_none());
}

fn build_json_cmw(
    component_id: &str,
    evidence_bytes: &[u8],
    evidence_type: &str,
    entries: Vec<(&str, &str, Vec<u8>, u64)>,
) -> Vec<u8> {
    let eat = json!({
        "eat_profile": TRUSTMEE_EAT_PROFILE,
        "component_id": component_id,
        "evidence_type": evidence_type,
        "evidence": URL_SAFE_NO_PAD.encode(evidence_bytes),
    });
    let eat_payload = serde_json::to_vec(&eat).expect("serialize JSON EAT");

    let mut collection = serde_json::Map::new();
    collection.insert(
        "__cmwc_t".to_string(),
        serde_json::Value::String(TRUSTMEE_COLLECTION_TYPE.to_string()),
    );
    collection.insert(
        "evidence".to_string(),
        json!([
            format!(
                "application/eat-ucs+json; eat_profile=\"{}\"",
                TRUSTMEE_EAT_PROFILE
            ),
            URL_SAFE_NO_PAD.encode(eat_payload),
            CMW_INDICATOR_EVIDENCE
        ]),
    );

    for (label, media_type, payload, indicator) in entries {
        collection.insert(
            label.to_string(),
            json!([media_type, URL_SAFE_NO_PAD.encode(payload), indicator]),
        );
    }

    serde_json::to_vec(&collection).expect("serialize JSON CMW")
}

fn build_cbor_cmw(
    component_id: &str,
    evidence_bytes: &[u8],
    evidence_type: &str,
    entries: Vec<(&str, &str, Vec<u8>, u64)>,
) -> Vec<u8> {
    let eat = CborEatClaims {
        eat_profile: TRUSTMEE_EAT_PROFILE.to_string(),
        component_id: component_id.to_string(),
        evidence: evidence_bytes.to_vec(),
        evidence_type: evidence_type.to_string(),
    };
    let mut eat_payload = Vec::new();
    into_writer(&eat, &mut eat_payload).expect("encode CBOR EAT");

    let mut collection: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    collection.insert(
        "__cmwc_t".to_string(),
        serde_json::Value::String(TRUSTMEE_COLLECTION_TYPE.to_string()),
    );
    collection.insert(
        "evidence".to_string(),
        json!([
            format!(
                "application/eat-ucs+cbor; eat_profile=\"{}\"",
                TRUSTMEE_EAT_PROFILE
            ),
            URL_SAFE_NO_PAD.encode(eat_payload),
            CMW_INDICATOR_EVIDENCE
        ]),
    );

    for (label, media_type, payload, indicator) in entries {
        collection.insert(
            label.to_string(),
            json!([media_type, URL_SAFE_NO_PAD.encode(payload), indicator]),
        );
    }

    let mut cbor_json = Vec::new();
    let as_json = serde_json::to_vec(&collection).expect("serialize CBOR helper JSON");
    let parsed_json: serde_json::Value =
        serde_json::from_slice(&as_json).expect("parse CBOR helper JSON");
    let cbor_value = json_to_cbor_value(&parsed_json);
    into_writer(&cbor_value, &mut cbor_json).expect("serialize CBOR CMW");
    cbor_json
}

fn json_to_cbor_value(value: &serde_json::Value) -> ciborium::value::Value {
    match value {
        serde_json::Value::Null => ciborium::value::Value::Null,
        serde_json::Value::Bool(value) => ciborium::value::Value::Bool(*value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                ciborium::value::Value::Integer(value.into())
            } else if let Some(value) = value.as_i64() {
                ciborium::value::Value::Integer(value.into())
            } else {
                ciborium::value::Value::Float(value.as_f64().expect("float"))
            }
        }
        serde_json::Value::String(value) => {
            if let Ok(bytes) = URL_SAFE_NO_PAD.decode(value) {
                ciborium::value::Value::Bytes(bytes)
            } else {
                ciborium::value::Value::Text(value.clone())
            }
        }
        serde_json::Value::Array(values) => {
            ciborium::value::Value::Array(values.iter().map(json_to_cbor_value).collect())
        }
        serde_json::Value::Object(values) => ciborium::value::Value::Map(
            values
                .iter()
                .map(|(key, value)| {
                    (
                        ciborium::value::Value::Text(key.clone()),
                        json_to_cbor_value(value),
                    )
                })
                .collect(),
        ),
    }
}

fn unique_test_dir(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = env::temp_dir().join(format!("{prefix}-{}-{now:x}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    dir
}

fn trust_store_path(prefix: &str) -> PathBuf {
    unique_test_dir(prefix).join("component-trust-store.json")
}

fn write_trust_store(path: &std::path::Path, signers: Vec<(String, i64, bool, &str)>) {
    let signers = signers
        .into_iter()
        .map(|(public_key, fuel, allow_network, valid_until)| {
            json!({
                "public_key": public_key,
                "fuel": fuel,
                "allow_network": allow_network,
                "valid_until": valid_until,
            })
        })
        .collect::<Vec<_>>();
    let json = json!({ "signers": signers });
    fs::write(
        path,
        serde_json::to_vec_pretty(&json).expect("serialize trust store"),
    )
    .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn cached_component_path(options: &VerifyOptions, component_id: &str) -> PathBuf {
    options
        .cache_dir
        .join("components")
        .join(format!("{component_id}.wasm"))
}

fn run_async<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create tokio runtime for wasm_pkg_client tests")
        .block_on(future)
}

fn component_version_for_id(component_id: &str) -> WasmPkgVersion {
    let digest = component_id
        .strip_prefix("component-")
        .expect("component_id prefix");
    format!("0.0.0-component.sha{digest}")
        .parse()
        .expect("parse component version")
}

fn test_registry_package() -> WasmPkgPackageRef {
    "trustmee:verifier-components"
        .parse()
        .expect("parse package ref")
}

fn create_empty_oci_file_store() -> String {
    let repo_root = unique_test_dir("trustmee-empty-oci-store");
    format!(
        "file://{}/trustmee/verifier-components",
        repo_root.display()
    )
}

fn create_oci_file_store(component_id: &str, wasm_bytes: Vec<u8>) -> String {
    let repo_root = unique_test_dir("trustmee-oci-store");
    let hint = format!(
        "file://{}/trustmee/verifier-components",
        repo_root.display()
    );
    let publish_input = repo_root.join("publish-input.wasm");
    fs::write(&publish_input, wasm_bytes).expect("write publish input");

    let package = test_registry_package();
    let version = component_version_for_id(component_id);
    let publish_root = repo_root.display().to_string();

    run_async(async move {
        let config = WasmPkgConfig::from_toml(&format!(
            r#"
[package_registry_overrides]
"{package}" = "local.trustmee.test"

[registry."local.trustmee.test"]
type = "local"
[registry."local.trustmee.test".local]
root = "{root}"
"#,
            package = package,
            root = publish_root,
        ))
        .expect("build local wasm_pkg_client config");
        let client = WasmPkgClient::new(config);
        client
            .publish_release_file(
                &publish_input,
                WasmPkgPublishOpts {
                    package: Some((package, version)),
                    registry: Some("local.trustmee.test".parse().expect("parse registry")),
                },
            )
            .await
            .expect("publish local test component");
    });

    hint
}

#[test]
fn verify_json_cmw_with_stapled_component_and_snp_collateral(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                component_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let result = verifier.verify_cmw_bytes(&cmw, None, None, &default_options())?;
    assert_snp_basic_claims(&result);
    assert_tee_type(&result, "snp");
    assert_component_hash(&result, &component_bytes);
    Ok(())
}

#[test]
fn verify_json_cmw_with_stapled_plain_snp_component_and_snp_collateral(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = plain_snp_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                component_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let result = verifier.verify_cmw_bytes(&cmw, None, None, &default_options())?;
    assert_snp_basic_claims(&result);
    assert_tee_type(&result, "snp");
    assert_component_hash(&result, &component_bytes);
    Ok(())
}

#[test]
fn verify_cbor_cmw_with_stapled_component_and_snp_collateral(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_cbor_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                component_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let result = verifier.verify_cmw_bytes(&cmw, None, None, &default_options())?;
    assert_snp_basic_claims(&result);
    assert_tee_type(&result, "snp");
    assert_component_hash(&result, &component_bytes);
    Ok(())
}

#[test]
#[ignore = "requires Intel collateral connectivity or a pre-populated cache"]
fn verify_json_cmw_with_stapled_tdx_component_and_quote() -> Result<(), Box<dyn std::error::Error>>
{
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = tdx_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let quote_bytes = tdx_quote_bytes();

    let cmw = build_json_cmw(
        &component_id,
        &quote_bytes,
        "application/octet-stream",
        vec![(
            "verifier",
            "application/wasm",
            component_bytes.clone(),
            CMW_INDICATOR_ENDORSEMENT,
        )],
    );

    let result = verifier.verify_cmw_bytes(&cmw, None, None, &default_options())?;
    assert_output_eat_profile(&result);
    assert!(
        claims(&result).get("quote").is_some(),
        "quote claim must be present"
    );
    assert_tee_type(&result, "tdx");
    assert_component_hash(&result, &component_bytes);
    assert!(
        claims(&result)
            .get("tcb_status")
            .and_then(|value| value.as_str())
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "tcb_status claim must be present"
    );
    Ok(())
}

#[test]
fn verify_cmw_fetches_component_from_oci_hint() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();
    let component_repository_hint = create_oci_file_store(&component_id, component_bytes.clone());

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![(
            "snp-collateral",
            SNP_COLLATERAL_MEDIA_TYPE,
            collateral_bytes,
            CMW_INDICATOR_ENDORSEMENT,
        )],
    );

    let mut options = default_options();
    options.component_repository_hint = Some(component_repository_hint);
    let result = verifier.verify_cmw_bytes(&cmw, None, None, &options)?;

    assert_snp_basic_claims(&result);
    assert_tee_type(&result, "snp");
    assert_component_hash(&result, &component_bytes);
    Ok(())
}

#[test]
fn verify_cmw_rejects_fetched_component_digest_mismatch() {
    let verifier = WasmVerificationComponent::new().expect("create verifier");
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();
    let component_repository_hint = create_oci_file_store(&component_id, b"wrong-bytes".to_vec());

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![(
            "snp-collateral",
            SNP_COLLATERAL_MEDIA_TYPE,
            collateral_bytes,
            CMW_INDICATOR_ENDORSEMENT,
        )],
    );

    let mut options = default_options();
    options.component_repository_hint = Some(component_repository_hint);
    let err = verifier
        .verify_cmw_bytes(&cmw, None, None, &options)
        .expect_err("digest mismatch must fail");

    assert!(
        format!("{err:#}").contains("digest mismatch"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn verify_cmw_uses_loaded_component_when_stapled_component_missing_and_disk_cache_removed(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let mut options = default_options();
    options.cache_dir = unique_test_dir("trustmee-cmw-cache-no-staple");

    let prime_cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );
    let prime_result = verifier.verify_cmw_bytes(&prime_cmw, None, None, &options)?;
    assert_snp_basic_claims(&prime_result);

    let disk_cache_path = cached_component_path(&options, &component_id);
    fs::remove_file(&disk_cache_path)
        .unwrap_or_else(|e| panic!("remove {}: {e}", disk_cache_path.display()));
    assert!(
        !disk_cache_path.exists(),
        "disk cache entry should be removed: {}",
        disk_cache_path.display()
    );

    let no_staple_cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![(
            "snp-collateral",
            SNP_COLLATERAL_MEDIA_TYPE,
            collateral_bytes,
            CMW_INDICATOR_ENDORSEMENT,
        )],
    );
    let result = verifier.verify_cmw_bytes(&no_staple_cmw, None, None, &options)?;

    assert_snp_basic_claims(&result);
    Ok(())
}

#[test]
fn verify_cmw_uses_disk_cached_component_in_fresh_verifier_when_stapled_component_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let prime_verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let mut options = default_options();
    options.cache_dir = unique_test_dir("trustmee-cmw-cache-fresh-verifier");

    let prime_cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );
    let prime_result = prime_verifier.verify_cmw_bytes(&prime_cmw, None, None, &options)?;
    assert_snp_basic_claims(&prime_result);
    let disk_cache_path = cached_component_path(&options, &component_id);
    assert!(
        disk_cache_path.exists(),
        "disk cache entry should exist after prime request: {}",
        disk_cache_path.display()
    );

    let fresh_verifier = WasmVerificationComponent::new()?;
    let no_staple_cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![(
            "snp-collateral",
            SNP_COLLATERAL_MEDIA_TYPE,
            collateral_bytes,
            CMW_INDICATOR_ENDORSEMENT,
        )],
    );
    let result = fresh_verifier.verify_cmw_bytes(&no_staple_cmw, None, None, &options)?;

    assert_snp_basic_claims(&result);
    Ok(())
}

#[test]
fn verify_cmw_prefers_loaded_component_over_stapled_component(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let mut options = default_options();
    options.cache_dir = unique_test_dir("trustmee-cmw-cache-prefer-local");

    let prime_cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );
    let prime_result = verifier.verify_cmw_bytes(&prime_cmw, None, None, &options)?;
    assert_snp_basic_claims(&prime_result);

    let bad_staple_cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                b"definitely-not-the-component".to_vec(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );
    let result = verifier.verify_cmw_bytes(&bad_staple_cmw, None, None, &options)?;

    assert_snp_basic_claims(&result);
    Ok(())
}

#[test]
fn verify_cmw_returns_missing_wasm_component_error() {
    let verifier = WasmVerificationComponent::new().expect("create verifier");
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![(
            "snp-collateral",
            SNP_COLLATERAL_MEDIA_TYPE,
            collateral_bytes,
            CMW_INDICATOR_ENDORSEMENT,
        )],
    );

    let mut options = default_options();
    options.cache_dir = unique_test_dir("trustmee-cmw-cache-missing-component");
    options.component_repository_hint = Some(create_empty_oci_file_store());

    let err = verifier
        .verify_cmw_bytes(&cmw, None, None, &options)
        .expect_err("missing component must fail");
    assert!(
        format!("{err:#}").contains("missing wasm component"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn verify_cmw_rejects_duplicate_evidence_entries() {
    let verifier = WasmVerificationComponent::new().expect("create verifier");
    let component_bytes = host_crypto_component_bytes();
    let component_id = component_id_for_component_bytes(&component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let mut collection: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&build_json_cmw(
            &component_id,
            &report_bytes,
            "application/octet-stream",
            vec![
                (
                    "verifier",
                    "application/wasm",
                    component_bytes,
                    CMW_INDICATOR_ENDORSEMENT,
                ),
                (
                    "snp-collateral",
                    SNP_COLLATERAL_MEDIA_TYPE,
                    collateral_bytes,
                    CMW_INDICATOR_ENDORSEMENT,
                ),
            ],
        ))
        .expect("parse test CMW JSON");
    collection.insert(
        "evidence-duplicate".to_string(),
        collection
            .get("evidence")
            .cloned()
            .expect("duplicate evidence"),
    );
    let bad_cmw = serde_json::to_vec(&collection).expect("serialize bad CMW");

    let err = verifier
        .verify_cmw_bytes(&bad_cmw, None, None, &default_options())
        .expect_err("duplicate Evidence must fail");
    assert!(
        format!("{err:#}").contains("exactly one Evidence entry"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn verify_cmw_accepts_signed_component_with_trusted_signer_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let (signed_component_bytes, public_key) = sign_component_bytes(&component_bytes);
    let component_id = component_id_for_component_bytes(&signed_component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                signed_component_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let mut options = default_options();
    let trust_store = trust_store_path("trustmee-cmw-trusted-signer");
    write_trust_store(
        &trust_store,
        vec![(public_key.to_pem(), -1, false, "2030-01-01T00:00:00Z")],
    );
    options.component_trust_store = Some(trust_store);

    let result = verifier.verify_cmw_bytes(&cmw, None, None, &options)?;
    assert_snp_basic_claims(&result);
    assert_tee_type(&result, "snp");
    assert_component_hash(&result, &signed_component_bytes);
    Ok(())
}

#[test]
fn verify_cmw_rejects_signed_component_with_untrusted_signer() {
    let verifier = WasmVerificationComponent::new().expect("create verifier");
    let component_bytes = host_crypto_component_bytes();
    let (signed_component_bytes, _public_key) = sign_component_bytes(&component_bytes);
    let component_id = component_id_for_component_bytes(&signed_component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();
    let untrusted_key = KeyPair::generate().pk.attach_default_key_id();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                signed_component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let mut options = default_options();
    let trust_store = trust_store_path("trustmee-cmw-untrusted-signer");
    write_trust_store(
        &trust_store,
        vec![(untrusted_key.to_pem(), 1234, true, "2030-01-01T00:00:00Z")],
    );
    options.component_trust_store = Some(trust_store);

    let err = verifier
        .verify_cmw_bytes(&cmw, None, None, &options)
        .expect_err("untrusted signer must fail");
    assert!(
        format!("{err:#}").contains("did not verify against any trusted public key"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn verify_cmw_rejects_signed_component_with_expired_signer() {
    let verifier = WasmVerificationComponent::new().expect("create verifier");
    let component_bytes = host_crypto_component_bytes();
    let (signed_component_bytes, public_key) = sign_component_bytes(&component_bytes);
    let component_id = component_id_for_component_bytes(&signed_component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                signed_component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let mut options = default_options();
    let trust_store = trust_store_path("trustmee-cmw-expired-signer");
    write_trust_store(
        &trust_store,
        vec![(public_key.to_pem(), 1234, true, "1970-01-01T00:00:01Z")],
    );
    options.component_trust_store = Some(trust_store);

    let err = verifier
        .verify_cmw_bytes(&cmw, None, None, &options)
        .expect_err("expired signer must fail");
    assert!(
        format!("{err:#}").contains("expired trusted public key"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn verify_cmw_rejects_component_when_multiple_trusted_signers_match() {
    let verifier = WasmVerificationComponent::new().expect("create verifier");
    let component_bytes = host_crypto_component_bytes();
    let (multi_signed_component_bytes, public_keys) = multi_sign_component_bytes(&component_bytes);
    let component_id = component_id_for_component_bytes(&multi_signed_component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                multi_signed_component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let mut options = default_options();
    let trust_store = trust_store_path("trustmee-cmw-multi-signer");
    write_trust_store(
        &trust_store,
        public_keys
            .iter()
            .map(|public_key| (public_key.to_pem(), 1234, true, "2030-01-01T00:00:00Z"))
            .collect(),
    );
    options.component_trust_store = Some(trust_store);

    let err = verifier
        .verify_cmw_bytes(&cmw, None, None, &options)
        .expect_err("multiple trusted signers must fail");
    assert!(
        format!("{err:#}").contains("multiple trusted public keys"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn verify_cmw_reloads_trust_store_for_cached_component() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = host_crypto_component_bytes();
    let (signed_component_bytes, public_key) = sign_component_bytes(&component_bytes);
    let component_id = component_id_for_component_bytes(&signed_component_bytes);
    let (report_bytes, collateral_bytes) = snp_report_and_collateral();

    let cmw = build_json_cmw(
        &component_id,
        &report_bytes,
        "application/octet-stream",
        vec![
            (
                "verifier",
                "application/wasm",
                signed_component_bytes.clone(),
                CMW_INDICATOR_ENDORSEMENT,
            ),
            (
                "snp-collateral",
                SNP_COLLATERAL_MEDIA_TYPE,
                collateral_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            ),
        ],
    );

    let mut options = default_options();
    let trust_store = trust_store_path("trustmee-cmw-reload-trust-store");
    write_trust_store(
        &trust_store,
        vec![(public_key.to_pem(), -1, true, "2030-01-01T00:00:00Z")],
    );
    options.component_trust_store = Some(trust_store.clone());

    let first_result = verifier.verify_cmw_bytes(&cmw, None, None, &options)?;
    assert_snp_basic_claims(&first_result);

    write_trust_store(
        &trust_store,
        vec![(public_key.to_pem(), 1234, true, "1970-01-01T00:00:01Z")],
    );

    let err = verifier
        .verify_cmw_bytes(&cmw, None, None, &options)
        .expect_err("expired trust store entry must be re-evaluated");
    assert!(
        format!("{err:#}").contains("expired trusted public key"),
        "unexpected error: {err:#}"
    );

    Ok(())
}

#[test]
fn verify_bytes_keeps_legacy_behavior_without_trust_store_and_accepts_trust_store_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = WasmVerificationComponent::new()?;
    let component_bytes = sample_plain_snp_component_bytes();
    let evidence_bytes = sample_snp_evidence_json_bytes();
    let (signed_component_bytes, public_key) = sign_component_bytes(&component_bytes);

    let legacy_result = verifier.verify_bytes(
        &signed_component_bytes,
        &evidence_bytes,
        None,
        None,
        &default_options(),
    )?;
    assert_tee_type(&legacy_result, "snp");
    assert_eq!(legacy_result["reported_tcb_snp"], 23);

    let mut options = default_options();
    let trust_store = trust_store_path("trustmee-direct-trusted-signer");
    write_trust_store(
        &trust_store,
        vec![(public_key.to_pem(), -1, true, "2030-01-01T00:00:00Z")],
    );
    options.component_trust_store = Some(trust_store);

    let trusted_result = verifier.verify_bytes(
        &signed_component_bytes,
        &evidence_bytes,
        None,
        None,
        &options,
    )?;
    assert_tee_type(&trusted_result, "snp");
    assert_eq!(trusted_result["reported_tcb_snp"], 23);
    assert_component_hash(&trusted_result, &signed_component_bytes);

    Ok(())
}
