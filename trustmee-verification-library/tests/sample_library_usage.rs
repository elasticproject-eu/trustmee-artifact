use sha2::{Digest, Sha256};
use std::path::PathBuf;
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn expected_component_hash(
    component_path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let component_bytes = std::fs::read(component_path)?;
    Ok(hex::encode(Sha256::digest(component_bytes)))
}

fn assert_snp_hex_claims(result: &serde_json::Value) {
    let measurement = result["measurement"]
        .as_str()
        .expect("measurement claim must be a string");
    let report_data = result["report_data"]
        .as_str()
        .expect("report_data claim must be a string");
    let init_data = result["init_data"]
        .as_str()
        .expect("init_data claim must be a string");

    assert_eq!(measurement.len(), 96, "measurement should be 96 hex chars");
    assert_eq!(
        report_data.len(),
        128,
        "report_data should be 128 hex chars"
    );
    assert_eq!(init_data.len(), 64, "init_data should be 64 hex chars");

    hex::decode(measurement).expect("measurement should decode as hex");
    hex::decode(report_data).expect("report_data should decode as hex");
    hex::decode(init_data).expect("init_data should decode as hex");
}

fn assert_tee_type(result: &serde_json::Value, expected: &str) {
    assert_eq!(result["tee_type"].as_str(), Some(expected));
}

fn assert_no_component_signature_public_key(result: &serde_json::Value) {
    assert!(
        result
            .get("verifier_component_signature_public_key")
            .is_none(),
        "verifier components without a validated signature should not include a signature public-key claim"
    );
}

#[test]
fn sample_library_usage_with_snp_json_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let project_root = project_root();

    let component_path = project_root.join("test_data/snp_verifier_component.wasm");
    let evidence_path = project_root.join("test_data/snp_evidence.json");

    assert!(
        component_path.exists(),
        "sample test requires verifier component at {}",
        component_path.display()
    );
    assert!(
        evidence_path.exists(),
        "sample test requires evidence file at {}",
        evidence_path.display()
    );

    let verifier = WasmVerificationComponent::new()?;
    let options = VerifyOptions {
        cache_dir: project_root.join(".wasm-verification-component-sample-test-cache"),
        pccs_url: None,
        component_repository_hint: None,
        component_trust_store: None,
    };

    let result = verifier.verify_paths(component_path, evidence_path, None, None, &options)?;
    let expected_hash =
        expected_component_hash(&project_root.join("test_data/snp_verifier_component.wasm"))?;

    assert_eq!(result["reported_tcb_snp"], 23);
    assert_eq!(result["reported_tcb_bootloader"], 10);
    assert_tee_type(&result, "snp");
    assert_eq!(
        result["verifier_component_sha256"].as_str(),
        Some(expected_hash.as_str())
    );
    assert_no_component_signature_public_key(&result);
    assert_snp_hex_claims(&result);
    assert!(
        result
            .get("measurement")
            .and_then(|v| v.as_str())
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "measurement claim must be present"
    );

    Ok(())
}

#[test]
fn sample_library_usage_with_snp_json_evidence_and_host_crypto_component(
) -> Result<(), Box<dyn std::error::Error>> {
    let project_root = project_root();

    let component_path = project_root.join("test_data/snp_verifier_host_crypto_component.wasm");
    let evidence_path = project_root.join("test_data/snp_evidence.json");

    assert!(
        component_path.exists(),
        "sample test requires verifier component at {}",
        component_path.display()
    );
    assert!(
        evidence_path.exists(),
        "sample test requires evidence file at {}",
        evidence_path.display()
    );

    let verifier = WasmVerificationComponent::new()?;
    let options = VerifyOptions {
        cache_dir: project_root.join(".wasm-verification-component-sample-host-crypto-cache"),
        pccs_url: None,
        component_repository_hint: None,
        component_trust_store: None,
    };

    let result = verifier.verify_paths(component_path, evidence_path, None, None, &options)?;
    let expected_hash = expected_component_hash(
        &project_root.join("test_data/snp_verifier_host_crypto_component.wasm"),
    )?;

    assert_eq!(result["reported_tcb_snp"], 23);
    assert_eq!(result["reported_tcb_bootloader"], 10);
    assert_tee_type(&result, "snp");
    assert_eq!(
        result["verifier_component_sha256"].as_str(),
        Some(expected_hash.as_str())
    );
    assert_no_component_signature_public_key(&result);
    assert_snp_hex_claims(&result);
    assert!(
        result
            .get("measurement")
            .and_then(|v| v.as_str())
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "measurement claim must be present"
    );

    Ok(())
}

#[test]
fn sample_library_usage_with_sample_signed_snp_component_and_trust_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let project_root = project_root();

    let component_path =
        project_root.join("test_data/signature-demo/snp_verifier_component.signed.wasm");
    let evidence_path = project_root.join("test_data/snp_evidence.json");
    let trust_store_path =
        project_root.join("test_data/signature-demo/snp_verifier_component.trust-store.json");

    assert!(
        component_path.exists(),
        "sample test requires signed verifier component at {}",
        component_path.display()
    );
    assert!(
        evidence_path.exists(),
        "sample test requires evidence file at {}",
        evidence_path.display()
    );
    assert!(
        trust_store_path.exists(),
        "sample test requires trust store at {}",
        trust_store_path.display()
    );

    let verifier = WasmVerificationComponent::new()?;
    let options = VerifyOptions {
        cache_dir: project_root.join(".wasm-verification-component-sample-signed-cache"),
        pccs_url: None,
        component_repository_hint: None,
        component_trust_store: Some(trust_store_path),
    };

    let result = verifier.verify_paths(component_path, evidence_path, None, None, &options)?;
    let expected_hash =
        expected_component_hash(&project_root.join("test_data/snp_verifier_component.wasm"))?;
    let expected_public_key = std::fs::read_to_string(
        project_root.join("test_data/signature-demo/snp_verifier_component.public.pem"),
    )?;

    assert_eq!(result["reported_tcb_snp"], 23);
    assert_eq!(result["reported_tcb_bootloader"], 10);
    assert_tee_type(&result, "snp");
    assert_eq!(
        result["verifier_component_sha256"].as_str(),
        Some(expected_hash.as_str())
    );
    assert_eq!(
        result["verifier_component_signature_public_key"].as_str(),
        Some(expected_public_key.as_str())
    );
    assert_snp_hex_claims(&result);

    Ok(())
}

#[test]
fn sample_library_usage_with_tdx_quote() -> Result<(), Box<dyn std::error::Error>> {
    let project_root = project_root();
    let component_path = project_root.join("test_data/tdx_verifier_component.wasm");
    let evidence_path = project_root.join("test_data/tdx_quote.bin");

    assert!(
        component_path.exists(),
        "sample test requires verifier component at {}",
        component_path.display()
    );
    assert!(
        evidence_path.exists(),
        "sample test requires evidence file at {}",
        evidence_path.display()
    );

    let verifier = WasmVerificationComponent::new()?;
    let options = VerifyOptions {
        cache_dir: project_root.join(".wasm-verification-component-sample-tdx-cache"),
        pccs_url: std::env::var("WASM_VERIFICATION_COMPONENT_PCCS_URL").ok(),
        component_repository_hint: None,
        component_trust_store: None,
    };

    let result = verifier.verify_paths(component_path, evidence_path, None, None, &options)?;
    let expected_hash =
        expected_component_hash(&project_root.join("test_data/tdx_verifier_component.wasm"))?;

    assert!(result.get("quote").is_some(), "quote claim must be present");
    assert_tee_type(&result, "tdx");
    assert_eq!(
        result["verifier_component_sha256"].as_str(),
        Some(expected_hash.as_str())
    );
    assert_no_component_signature_public_key(&result);
    assert!(
        result
            .get("tcb_status")
            .and_then(|v| v.as_str())
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "tcb_status claim must be present"
    );

    Ok(())
}
