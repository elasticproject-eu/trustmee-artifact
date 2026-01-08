use anyhow::{anyhow, Context, Result};
use serde_json::json;

mod snp;

wit_bindgen::generate!({
    path: "wit",
    world: "verifier",
});

fn evaluate_impl(
    evidence: Vec<u8>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String> {
    let evidence = snp::parse_evidence_bytes(&evidence).context("parse SNP evidence")?;
    let claims = snp::evaluate(
        &snp::Snp::new(),
        evidence,
        expected_report_data.as_deref(),
        expected_init_data_hash.as_deref(),
    )?;
    let claim_map = claims
        .as_object()
        .ok_or_else(|| anyhow!("claims map is not a JSON object"))?;
    Ok(serde_json::to_string(claim_map)?)
}

struct Component;

impl exports::trustee::verifier::verifier_interface::Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;

impl exports::trustee::verifier::verifier_interface::GuestVerifier for Verifier {
    fn new() -> Self {
        Self
    }

    fn evaluate(
        &self,
        evidence: Vec<u8>,
        expected_report_data: exports::trustee::verifier::verifier_interface::OptionalData,
        expected_init_data_hash: exports::trustee::verifier::verifier_interface::OptionalData,
    ) -> String {
        let expected_report_data = match expected_report_data {
            exports::trustee::verifier::verifier_interface::OptionalData::Value(v) => Some(v),
            exports::trustee::verifier::verifier_interface::OptionalData::NotProvided => None,
        };
        let expected_init_data_hash = match expected_init_data_hash {
            exports::trustee::verifier::verifier_interface::OptionalData::Value(v) => Some(v),
            exports::trustee::verifier::verifier_interface::OptionalData::NotProvided => None,
        };

        match evaluate_impl(evidence, expected_report_data, expected_init_data_hash) {
            Ok(v) => v,
            Err(e) => json!({
                "status": "failed",
                "error": format!("{e:#}"),
            })
            .to_string(),
        }
    }
}

export!(Component);
