use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

const RTMR_BYTE_LEN: usize = 48;
const DEFAULT_RTMR0_HEX: &str =
    "5b5e0154250ff5a23e9f4d9df9e711d6c58ffb3a82f6b79daa5890f568d947b6ddcf54bae44aad2cfeb5022afc913c50";
const DEFAULT_RTMR1_HEX: &str =
    "86d9724fbe612a44d56155157dbdaf83fbb709e3f005fe7bf67d30738dbc0b8b4f4284bb73438508933bc8472039483a";

wit_bindgen::generate!({
    path: "wit",
    world: "bootloader-verifier",
});

fn parse_expected_rtmr(field: &str, value: Option<&str>, default_hex: &str) -> Result<Vec<u8>> {
    let source = value.unwrap_or(default_hex).trim();
    let source = source.strip_prefix("0x").unwrap_or(source);
    let bytes = hex::decode(source).with_context(|| format!("decode {field} hex"))?;
    if bytes.len() != RTMR_BYTE_LEN {
        bail!(
            "{field} must be {RTMR_BYTE_LEN} bytes ({} hex chars), got {} bytes",
            RTMR_BYTE_LEN * 2,
            bytes.len()
        );
    }
    Ok(bytes)
}

fn split_evidence_and_reference(
    input: &exports::trustee::verifier::verifier_interface::VerifierInput,
) -> Result<(
    trustee::verifier::verifier_interface::VerifierInput,
    Option<String>,
    Option<String>,
)> {
    let value: Value = match serde_json::from_slice(&input.evidence) {
        Ok(v) => v,
        Err(_) => return Ok((normalize_verifier_input(input), None, None)),
    };

    let obj = match value.as_object() {
        Some(v) => v,
        None => return Ok((normalize_verifier_input(input), None, None)),
    };

    let expected_rtmr0 = obj
        .get("expected_rtmr0")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            obj.get("bootloader_reference")
                .and_then(Value::as_object)
                .and_then(|v| v.get("rtmr0"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });

    let expected_rtmr1 = obj
        .get("expected_rtmr1")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            obj.get("bootloader_reference")
                .and_then(Value::as_object)
                .and_then(|v| v.get("rtmr1"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });

    let (forwarded_evidence, forwarded_media_type) = match obj.get("tdx_evidence") {
        Some(Value::String(s)) => (
            s.as_bytes().to_vec(),
            "application/octet-stream".to_string(),
        ),
        Some(v) => (
            serde_json::to_vec(v).context("serialize `tdx_evidence`")?,
            "application/json".to_string(),
        ),
        None => (input.evidence.clone(), input.evidence_media_type.clone()),
    };

    Ok((
        trustee::verifier::verifier_interface::VerifierInput {
            evidence: forwarded_evidence,
            evidence_media_type: forwarded_media_type,
            endorsements: input
                .endorsements
                .iter()
                .map(
                    |endorsement| trustee::verifier::verifier_interface::Endorsement {
                        label: endorsement.label.clone(),
                        media_type: endorsement.media_type.clone(),
                        payload: endorsement.payload.clone(),
                    },
                )
                .collect(),
        },
        expected_rtmr0,
        expected_rtmr1,
    ))
}

fn normalize_optional_data(
    input: exports::trustee::verifier::verifier_interface::OptionalData,
) -> trustee::verifier::verifier_interface::OptionalData {
    match input {
        exports::trustee::verifier::verifier_interface::OptionalData::Value(v) => {
            trustee::verifier::verifier_interface::OptionalData::Value(v)
        }
        exports::trustee::verifier::verifier_interface::OptionalData::NotProvided => {
            trustee::verifier::verifier_interface::OptionalData::NotProvided
        }
    }
}

fn normalize_verifier_input(
    input: &exports::trustee::verifier::verifier_interface::VerifierInput,
) -> trustee::verifier::verifier_interface::VerifierInput {
    trustee::verifier::verifier_interface::VerifierInput {
        evidence: input.evidence.clone(),
        evidence_media_type: input.evidence_media_type.clone(),
        endorsements: input
            .endorsements
            .iter()
            .map(
                |endorsement| trustee::verifier::verifier_interface::Endorsement {
                    label: endorsement.label.clone(),
                    media_type: endorsement.media_type.clone(),
                    payload: endorsement.payload.clone(),
                },
            )
            .collect(),
    }
}

fn get_claim_str<'a>(claims: &'a Value, pointer: &str, field: &str) -> Result<&'a str> {
    claims
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing `{field}` in TDX verifier claims"))
}

fn evaluate_impl(
    input: exports::trustee::verifier::verifier_interface::VerifierInput,
    expected_report_data: exports::trustee::verifier::verifier_interface::OptionalData,
    expected_init_data_hash: exports::trustee::verifier::verifier_interface::OptionalData,
) -> Result<String> {
    let (forwarded_input, rtmr0_hex, rtmr1_hex) = split_evidence_and_reference(&input)?;
    let expected_rtmr0 =
        parse_expected_rtmr("expected_rtmr0", rtmr0_hex.as_deref(), DEFAULT_RTMR0_HEX)?;
    let expected_rtmr1 =
        parse_expected_rtmr("expected_rtmr1", rtmr1_hex.as_deref(), DEFAULT_RTMR1_HEX)?;

    let tdx_verifier = trustee::verifier::verifier_interface::Verifier::new();
    let tdx_out = tdx_verifier.evaluate(
        &forwarded_input,
        &normalize_optional_data(expected_report_data),
        &normalize_optional_data(expected_init_data_hash),
    );

    let claims: Value =
        serde_json::from_str(&tdx_out).context("TDX verifier returned non-JSON output")?;
    if claims.get("error").is_some() {
        return Ok(tdx_out);
    }

    let measured_rtmr0_hex = get_claim_str(&claims, "/quote/body/rtmr_0", "quote.body.rtmr_0")?;
    let measured_rtmr1_hex = get_claim_str(&claims, "/quote/body/rtmr_1", "quote.body.rtmr_1")?;
    let measured_rtmr0 = parse_expected_rtmr(
        "quote.body.rtmr_0",
        Some(measured_rtmr0_hex),
        DEFAULT_RTMR0_HEX,
    )?;
    let measured_rtmr1 = parse_expected_rtmr(
        "quote.body.rtmr_1",
        Some(measured_rtmr1_hex),
        DEFAULT_RTMR1_HEX,
    )?;

    if measured_rtmr0 != expected_rtmr0 {
        bail!(
            "bootloader RTMR0 mismatch: measured={}, expected={}",
            hex::encode(measured_rtmr0),
            hex::encode(expected_rtmr0)
        );
    }
    if measured_rtmr1 != expected_rtmr1 {
        bail!(
            "bootloader RTMR1 mismatch: measured={}, expected={}",
            hex::encode(measured_rtmr1),
            hex::encode(expected_rtmr1)
        );
    }

    let mut claims = claims
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("TDX claims are not a JSON object"))?;
    claims.insert("tee_type".to_string(), Value::String("tdx".to_string()));
    claims.insert("bootloader_verified".to_string(), Value::Bool(true));
    claims.insert(
        "bootloader_expected_rtmr0".to_string(),
        Value::String(hex::encode(expected_rtmr0)),
    );
    claims.insert(
        "bootloader_expected_rtmr1".to_string(),
        Value::String(hex::encode(expected_rtmr1)),
    );

    Ok(serde_json::to_string(&claims)?)
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
        input: exports::trustee::verifier::verifier_interface::VerifierInput,
        expected_report_data: exports::trustee::verifier::verifier_interface::OptionalData,
        expected_init_data_hash: exports::trustee::verifier::verifier_interface::OptionalData,
    ) -> String {
        match evaluate_impl(input, expected_report_data, expected_init_data_hash) {
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
