//! Kata agent-policy verification component.
//!
//! Sits above a hardware TEE verifier (TDX or SNP) in a composed component
//! chain: it imports `trustee:verifier/verifier-interface`, forwards the
//! evidence to the hardware layer for quote/report verification, and then
//! verifies that the Kata Containers agent policy embedded in the
//! confidential VM's init-data is (1) the init-data the hardware actually
//! measured (MRCONFIGID / HOSTDATA binding) and (2) structurally exactly one
//! approved static rules template plus one pure-JSON `policy_data`
//! assignment. All verification logic lives in `kata-policy-core`.

use serde_json::{json, Value};

wit_bindgen::generate!({
    path: "wit",
    world: "kata-policy-verifier",
});

use exports::trustee::verifier::verifier_interface as export_iface;
use trustee::verifier::verifier_interface as import_iface;

const INIT_DATA_LABEL: &str = "init-data";
const APPROVED_TEMPLATES_LABEL: &str = "approved-templates";

fn forward_input(input: &export_iface::VerifierInput) -> import_iface::VerifierInput {
    import_iface::VerifierInput {
        evidence: input.evidence.clone(),
        evidence_media_type: input.evidence_media_type.clone(),
        endorsements: input
            .endorsements
            .iter()
            .map(|e| import_iface::Endorsement {
                label: e.label.clone(),
                media_type: e.media_type.clone(),
                payload: e.payload.clone(),
            })
            .collect(),
    }
}

fn forward_optional(data: &export_iface::OptionalData) -> import_iface::OptionalData {
    match data {
        export_iface::OptionalData::Value(v) => import_iface::OptionalData::Value(v.clone()),
        export_iface::OptionalData::NotProvided => import_iface::OptionalData::NotProvided,
    }
}

fn find_endorsement<'a>(
    input: &'a export_iface::VerifierInput,
    label: &str,
) -> Result<&'a [u8], String> {
    let mut matches = input
        .endorsements
        .iter()
        .filter(|e| e.label == label)
        .map(|e| e.payload.as_slice());
    let first = matches
        .next()
        .ok_or_else(|| format!("missing required endorsement `{label}`"))?;
    if matches.next().is_some() {
        return Err(format!("duplicate endorsement `{label}`"));
    }
    Ok(first)
}

/// The hardware-measured init-data value from the lower layer's claims.
/// Both the TDX verifier (MRCONFIGID) and the SNP verifiers (HOSTDATA) in
/// this repository expose it as a top-level hex `init_data` claim.
fn measured_init_data(hw_claims: &Value) -> Result<Vec<u8>, String> {
    let hex_str = hw_claims
        .get("init_data")
        .and_then(Value::as_str)
        .ok_or("hardware claims have no `init_data` (MRCONFIGID/HOSTDATA) entry")?;
    hex::decode(hex_str.trim())
        .map_err(|e| format!("hardware `init_data` claim is not valid hex: {e}"))
}

fn parse_approved_templates(raw: &[u8]) -> Result<Vec<String>, String> {
    let value: Value = serde_json::from_slice(raw)
        .map_err(|e| format!("`{APPROVED_TEMPLATES_LABEL}` endorsement is not JSON: {e}"))?;
    let list = value
        .as_array()
        .ok_or(format!("`{APPROVED_TEMPLATES_LABEL}` must be a JSON array of sha256 hex strings"))?;
    list.iter()
        .map(|v| {
            let s = v
                .as_str()
                .ok_or("approved template entries must be strings")?;
            let trimmed = s.trim();
            if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("`{trimmed}` is not a sha256 hex digest"));
            }
            Ok(trimmed.to_ascii_lowercase())
        })
        .collect()
}

fn evaluate_impl(
    input: &export_iface::VerifierInput,
    expected_report_data: &export_iface::OptionalData,
    expected_init_data_hash: &export_iface::OptionalData,
) -> Result<String, String> {
    let init_data_raw = find_endorsement(input, INIT_DATA_LABEL)?.to_vec();
    let approved_templates = parse_approved_templates(find_endorsement(
        input,
        APPROVED_TEMPLATES_LABEL,
    )?)?;

    // Step 1a: the composed lower-layer hardware component verifies the
    // quote/report signature chain. Its failure is our failure.
    let hardware = import_iface::Verifier::new();
    let hw_out = hardware.evaluate(
        &forward_input(input),
        &forward_optional(expected_report_data),
        &forward_optional(expected_init_data_hash),
    );
    let hw_claims: Value = serde_json::from_str(&hw_out)
        .map_err(|e| format!("hardware verifier returned non-JSON claims: {e}"))?;
    if let Some(err) = hw_claims.get("error") {
        return Err(format!("hardware evidence verification failed: {err}"));
    }

    // Steps 1b-5: binding check, structural parse, template hash, facts.
    let measured = measured_init_data(&hw_claims)?;
    let kata_policy =
        kata_policy_core::evaluate_kata_policy(&init_data_raw, &approved_templates, &measured)?;

    serde_json::to_string(&json!({
        "kata_policy": kata_policy,
        "hardware": hw_claims,
    }))
    .map_err(|e| format!("serialize claims: {e}"))
}

struct Component;

impl export_iface::Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;

impl export_iface::GuestVerifier for Verifier {
    fn new() -> Self {
        Self
    }

    fn evaluate(
        &self,
        input: export_iface::VerifierInput,
        expected_report_data: export_iface::OptionalData,
        expected_init_data_hash: export_iface::OptionalData,
    ) -> String {
        match evaluate_impl(&input, &expected_report_data, &expected_init_data_hash) {
            Ok(claims) => claims,
            Err(e) => json!({
                "status": "failed",
                "error": e,
            })
            .to_string(),
        }
    }
}

export!(Component);
