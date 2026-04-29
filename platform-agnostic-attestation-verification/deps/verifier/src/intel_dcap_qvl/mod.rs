//! Native Intel DCAP verification via the pure-Rust `dcap-qvl` crate.
//!
//! This path mirrors the wasm TDX/SGX verifier component verification stack
//! (`dcap-qvl` + `dcap-qvl-wasi` for collateral fetch) but runs natively.
//! Gated by `*-verifier-dcap-qvl` features and activated at runtime by
//! `TDX_NATIVE_USE_DCAP_QVL=1` or `SGX_NATIVE_USE_DCAP_QVL=1`.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::intel_dcap::emit_collateral_timing_for_tee;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn parse_next_update_secs(json: &str) -> Option<u64> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let next_update = value.get("nextUpdate")?.as_str()?;
    let parsed = OffsetDateTime::parse(next_update, &Rfc3339).ok()?;
    Some(parsed.unix_timestamp().max(0) as u64)
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

fn claims_from_verified(report: dcap_qvl::verify::VerifiedReport) -> Map<String, Value> {
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

fn cache_dir() -> PathBuf {
    std::env::var("DCAP_QVL_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/dcap-qvl-cache"))
}

fn pccs_url() -> Option<String> {
    std::env::var("DCAP_QVL_PCCS_URL").ok()
}

/// Native equivalent of `ecdsa_quote_verification`. Fetches collateral via
/// `dcap-qvl-wasi` (with the `reqwest-http` backend for native builds) and
/// runs `dcap_qvl::verify::verify`.
pub async fn ecdsa_quote_verification_via_dcap_qvl(quote: &[u8]) -> Result<Map<String, Value>> {
    ecdsa_quote_verification_via_dcap_qvl_for_tee("Tdx", quote).await
}

pub async fn sgx_ecdsa_quote_verification_via_dcap_qvl(quote: &[u8]) -> Result<Map<String, Value>> {
    ecdsa_quote_verification_via_dcap_qvl_for_tee("Sgx", quote).await
}

async fn ecdsa_quote_verification_via_dcap_qvl_for_tee(
    tee: &'static str,
    quote: &[u8],
) -> Result<Map<String, Value>> {
    let cache = cache_dir();
    std::fs::create_dir_all(&cache)
        .with_context(|| format!("create dcap-qvl cache dir {}", cache.display()))?;

    let url = pccs_url();
    let quote_vec = quote.to_vec();
    let cache_path = cache.clone();

    let collateral_start = std::time::Instant::now();
    // dcap-qvl-wasi's get_collateral_cached is sync + blocking. Run it in a
    // blocking task so we don't stall the async executor.
    let collateral = tokio::task::spawn_blocking(move || {
        dcap_qvl_wasi::get_collateral_cached(url.as_deref(), &quote_vec, &cache_path)
    })
    .await
    .map_err(|e| anyhow!("dcap-qvl collateral fetch task join: {e}"))?
    .context("dcap-qvl collateral fetch")?;
    emit_collateral_timing_for_tee(tee, "native_dcap_qvl", collateral_start.elapsed());

    let now = now_secs();
    let verified = dcap_qvl::verify::verify(quote, &collateral, now)
        .map_err(|e| anyhow!("dcap-qvl verify failed: {e:?}"))?;

    let mut claims = claims_from_verified(verified);
    if collateral_expired(&collateral, now) {
        claims.insert("collateral_expired".to_string(), Value::Bool(true));
    }

    if !bail_on_verification_result(&claims)? {
        debug_verification_status(&claims);
    }

    Ok(claims)
}

fn bail_on_verification_result(claims: &Map<String, Value>) -> Result<bool> {
    // dcap-qvl verify() returns Ok only when the quote verified successfully;
    // the TCB status may still be "configNeeded" / "outOfDate" etc. Mirror the
    // original native path's acceptance of those benign statuses (see
    // intel_dcap::ecdsa_quote_verification for the list).
    let status = claims
        .get("tcb_status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match status {
        "UpToDate"
        | "OutOfDate"
        | "ConfigurationNeeded"
        | "OutOfDateConfigurationNeeded"
        | "SWHardeningNeeded"
        | "ConfigurationAndSWHardeningNeeded"
        | "TDRelaunchAdvised"
        | "TDRelaunchAdvisedConfigurationNeeded" => Ok(true),
        "" => Ok(true),
        terminal => bail!("dcap-qvl terminal TCB status: {terminal}"),
    }
}

fn debug_verification_status(claims: &Map<String, Value>) {
    tracing::debug!("dcap-qvl verified: {:?}", claims.get("tcb_status"));
}

/// Env-var helper: is the dcap-qvl native path selected at runtime?
pub fn use_dcap_qvl_native() -> bool {
    matches!(
        std::env::var("TDX_NATIVE_USE_DCAP_QVL").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Env-var helper: is the dcap-qvl native SGX path selected at runtime?
pub fn use_sgx_dcap_qvl_native() -> bool {
    matches!(
        std::env::var("SGX_NATIVE_USE_DCAP_QVL").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}
