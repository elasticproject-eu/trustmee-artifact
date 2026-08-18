//! Stub hardware verifier for kata-policy-verifier fixture tests.
//!
//! Stands in for the real TDX/SNP component so the composed stack can be
//! exercised without a live TEE. The "quote" (evidence) is a JSON document:
//!
//! ```json
//! { "valid": true, "claims": { "init_data": "<hex>", ... } }
//! ```
//!
//! `valid: false` simulates a quote whose signature chain fails to verify;
//! otherwise the embedded `claims` object is returned verbatim, exactly like
//! a real hardware verifier returning its parsed quote claims (both TDX and
//! SNP verifiers in this repo expose the measured MRCONFIGID/HOSTDATA as a
//! top-level hex `init_data` claim).

use serde_json::{json, Value};

wit_bindgen::generate!({
    path: "wit",
    world: "verifier",
});

use exports::trustee::verifier::verifier_interface as iface;

fn evaluate_impl(input: &iface::VerifierInput) -> Result<String, String> {
    let evidence: Value = serde_json::from_slice(&input.evidence)
        .map_err(|e| format!("stub evidence is not JSON: {e}"))?;

    if !evidence
        .get("valid")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("quote verification failed (stub: evidence marked invalid)".into());
    }

    let claims = evidence
        .get("claims")
        .and_then(Value::as_object)
        .ok_or("stub evidence has no `claims` object")?;

    serde_json::to_string(&Value::Object(claims.clone())).map_err(|e| e.to_string())
}

struct Component;

impl iface::Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;

impl iface::GuestVerifier for Verifier {
    fn new() -> Self {
        Self
    }

    fn evaluate(
        &self,
        input: iface::VerifierInput,
        _expected_report_data: iface::OptionalData,
        _expected_init_data_hash: iface::OptionalData,
    ) -> String {
        match evaluate_impl(&input) {
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
