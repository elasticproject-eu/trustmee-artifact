use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chrono::DateTime;
use dcap_qvl::verify::VerifiedReport;
use dcap_qvl::QuoteCollateralV3;
use eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

/// CMW endorsement media type that carries a pre-fetched TDX collateral
/// (`QuoteCollateralV3` serialized as CBOR). Keep this in sync with the host
/// constant in `trustmee_input::TDX_COLLATERAL_MEDIA_TYPE`.
const TDX_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.tdx-collateral+cbor";

/// Paper-evaluation: when set, the component emits per-step timing JSON lines
/// to stderr. Timing fields must not be returned as verifier claims.
fn timing_enabled() -> bool {
    std::env::var("WVC_EMIT_TIMING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn emit_collateral_fetch_timing(tee: &str, ms: f64) {
    if !timing_enabled() {
        return;
    }
    eprintln!(
        "{}",
        json!({
            "event": "as_tdx_collateral_timing",
            "tee": tee,
            "mode": "wasm",
            "ms": ms,
        })
    );
}

mod tdx {
    pub mod claims;
    pub mod quote;
}

type TeeEvidenceParsedClaim = serde_json::Value;

wit_bindgen::generate!({
    path: "wit",
    world: "verifier",
});

#[derive(Debug, Deserialize)]
struct TdxEvidenceJson {
    /// Base64 encoded CCEL ACPI table bytes.
    #[serde(default)]
    cc_eventlog: Option<String>,
    /// Optional PCCS URL for collateral lookup.
    #[serde(default)]
    pccs_url: Option<String>,
    /// Base64 encoded TDX quote bytes.
    quote: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn regularize_data(expected: &[u8], expected_len: usize, field: &str) -> Result<Vec<u8>> {
    if expected.len() > expected_len {
        bail!(
            "{field} length ({}) exceeds expected length ({expected_len})",
            expected.len()
        );
    }
    if expected.len() == expected_len {
        return Ok(expected.to_vec());
    }
    let mut out = Vec::with_capacity(expected_len);
    out.extend_from_slice(expected);
    out.extend(std::iter::repeat(0).take(expected_len - expected.len()));
    Ok(out)
}

fn custom_claims_from_verified_report(report: VerifiedReport) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("tcb_status".to_string(), Value::String(report.status));
    map.insert(
        "advisory_ids".to_string(),
        Value::Array(report.advisory_ids.into_iter().map(Value::String).collect()),
    );
    map.insert(
        "platform_provider_id".to_string(),
        Value::String(hex::encode(report.ppid)),
    );
    map
}

fn parse_next_update_secs(json: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let next_update = value.get("nextUpdate")?.as_str()?;
    let parsed = DateTime::parse_from_rfc3339(next_update).ok()?;
    Some(parsed.timestamp().max(0) as u64)
}

fn collateral_expired(collateral: &dcap_qvl::QuoteCollateralV3, now: u64) -> bool {
    for next_update in [
        parse_next_update_secs(&collateral.tcb_info),
        parse_next_update_secs(&collateral.qe_identity),
    ] {
        let Some(next_update) = next_update else {
            continue;
        };
        if now > next_update {
            return true;
        }
    }
    false
}

static PREOPEN_DIRS: LazyLock<Vec<String>> = LazyLock::new(|| {
    wasip2::filesystem::preopens::get_directories()
        .into_iter()
        .map(|(descriptor, path)| {
            // Keep returned descriptor handles alive for component lifetime.
            std::mem::forget(descriptor);
            path
        })
        .collect()
});

fn cache_root_from_preopens() -> Result<PathBuf> {
    for path in PREOPEN_DIRS.iter() {
        let candidate = PathBuf::from(path);
        if candidate.is_dir() {
            return Ok(candidate);
        }
    }

    PREOPEN_DIRS
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("no preopened directories from wasi:filesystem/preopens"))
}

fn ecdsa_quote_verification_via_dcap_qvl(
    quote: &[u8],
    pccs_url: Option<&str>,
    cmw_collateral: Option<QuoteCollateralV3>,
    timing: &mut TimingAccumulator,
) -> Result<Map<String, Value>> {
    let (collateral, collateral_fetch_ms) = match cmw_collateral {
        Some(c) => (c, 0.0_f64),
        None => {
            let cache_dir = cache_root_from_preopens()?.join("dcap-qvl-cache");
            let t0 = Instant::now();
            let c = dcap_qvl_wasi::get_collateral_cached(pccs_url, quote, &cache_dir)
                .context("get collateral")?;
            (c, t0.elapsed().as_secs_f64() * 1000.0)
        }
    };
    timing.collateral_fetch_ms = collateral_fetch_ms;
    let now = now_secs();
    let verified = dcap_qvl::verify::verify(quote, &collateral, now)
        .context("dcap-qvl quote verification failed")?;
    let mut claims = custom_claims_from_verified_report(verified);
    if collateral_expired(&collateral, now) {
        claims.insert("collateral_expired".to_string(), Value::Bool(true));
    }
    Ok(claims)
}

/// Per-request timing accumulator used only for paper-eval log events.
#[derive(Default)]
struct TimingAccumulator {
    collateral_fetch_ms: f64,
}

/// Look up a TDX collateral endorsement in the CMW and decode it.
fn cmw_tdx_collateral(
    endorsements: &[exports::trustee::verifier::verifier_interface::Endorsement],
) -> Result<Option<QuoteCollateralV3>> {
    for endorsement in endorsements {
        if endorsement.media_type != TDX_COLLATERAL_MEDIA_TYPE {
            continue;
        }
        let collateral: QuoteCollateralV3 =
            ciborium::de::from_reader(endorsement.payload.as_slice())
                .context("CBOR-decode TDX collateral endorsement")?;
        return Ok(Some(collateral));
    }
    Ok(None)
}

fn parse_evidence(evidence: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>, Option<String>)> {
    if let Ok(s) = std::str::from_utf8(evidence) {
        if s.trim_start().starts_with('{') {
            let ev: TdxEvidenceJson = serde_json::from_str(s).context("parse evidence JSON")?;
            if ev.quote.is_empty() {
                bail!("TDX Quote is empty");
            }
            let quote_bin = base64::engine::general_purpose::STANDARD
                .decode(ev.quote)
                .context("decode base64 quote")?;
            let ccel = match ev.cc_eventlog {
                Some(el) if !el.is_empty() => Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(el)
                        .context("decode base64 CCEL")?,
                ),
                _ => None,
            };
            return Ok((quote_bin, ccel, ev.pccs_url));
        }
    }
    Ok((evidence.to_vec(), None, None))
}

fn evaluate_impl(
    input: exports::trustee::verifier::verifier_interface::VerifierInput,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String> {
    let mut timing = TimingAccumulator::default();
    let (quote_bin, ccel_bin, pccs_url) = parse_evidence(&input.evidence)?;
    if quote_bin.is_empty() {
        bail!("TDX Quote is empty");
    }

    // Paper-eval: prefer CMW-provided TDX collateral over fetching from PCS.
    let cmw_collateral = cmw_tdx_collateral(&input.endorsements)?;

    let custom_claims = ecdsa_quote_verification_via_dcap_qvl(
        &quote_bin,
        pccs_url.as_deref(),
        cmw_collateral,
        &mut timing,
    )?;
    let quote = tdx::quote::parse_tdx_quote(&quote_bin).context("parse TDX quote")?;

    if let Some(expected) = expected_report_data {
        let expected = regularize_data(&expected, 64, "REPORT_DATA")?;
        if expected.as_slice() != quote.report_data() {
            bail!("REPORT_DATA is different from that in TDX Quote");
        }
    }

    if let Some(expected) = expected_init_data_hash {
        let expected = regularize_data(&expected, 48, "MRCONFIGID")?;
        if expected.as_slice() != quote.mr_config_id() {
            bail!("MRCONFIGID is different from that in TDX Quote");
        }
    }

    let ccel = match ccel_bin {
        Some(bin) if !bin.is_empty() => {
            let ccel =
                CcEventLog::try_from(bin).map_err(|e| anyhow!("Parse CCEL failed: {e:?}"))?;
            let compare_obj: Vec<ReferenceMeasurement> = vec![
                ReferenceMeasurement {
                    index: 1,
                    algorithm: TcgAlgorithm::Sha384,
                    reference: quote.rtmr_0().to_vec(),
                },
                ReferenceMeasurement {
                    index: 2,
                    algorithm: TcgAlgorithm::Sha384,
                    reference: quote.rtmr_1().to_vec(),
                },
                ReferenceMeasurement {
                    index: 3,
                    algorithm: TcgAlgorithm::Sha384,
                    reference: quote.rtmr_2().to_vec(),
                },
                ReferenceMeasurement {
                    index: 4,
                    algorithm: TcgAlgorithm::Sha384,
                    reference: quote.rtmr_3().to_vec(),
                },
            ];
            ccel.replay_and_match(compare_obj)?;
            Some(ccel)
        }
        _ => None,
    };

    let mut claim: TeeEvidenceParsedClaim =
        tdx::claims::generate_parsed_claim(quote, ccel).context("generate parsed claim")?;
    let Value::Object(ref mut claim_map) = claim else {
        bail!("claim is not a JSON object");
    };
    claim_map.insert("tee_type".to_string(), Value::String("tdx".to_string()));
    claim_map.extend(custom_claims);

    emit_collateral_fetch_timing("Tdx", timing.collateral_fetch_ms);

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
        input: exports::trustee::verifier::verifier_interface::VerifierInput,
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
