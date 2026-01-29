use anyhow::{Context, Result};
use ::dcap_qvl::verify::VerifiedReport;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const DEFAULT_PCS_URL: &str = "https://api.trustedservices.intel.com";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn cache_disabled() -> bool {
    std::env::var("DCAP_QVL_DISABLE_CACHE")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn cache_key(base_url: &str, tee: &str, fmspc: &str, ca: &str) -> String {
    let mut h = Sha256::new();
    h.update(base_url.as_bytes());
    let digest = h.finalize();
    let short = hex::encode(&digest[..4]);
    format!("collateral_{short}_{tee}_{fmspc}_{ca}.json")
}

fn normalize_base_url(pccs_url: &str) -> String {
    pccs_url
        .trim()
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4")
        .to_owned()
}

fn read_cache(cache_path: &Path) -> Option<::dcap_qvl::QuoteCollateralV3> {
    let data = fs::read(cache_path).ok()?;
    serde_json::from_slice(&data).ok()
}

fn write_cache(cache_path: &Path, collateral: &::dcap_qvl::QuoteCollateralV3) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let data = serde_json::to_vec(collateral).context("serialize collateral")?;
    fs::write(cache_path, data).with_context(|| format!("write {}", cache_path.display()))?;
    Ok(())
}

fn cached_collateral_is_fresh(collateral: &::dcap_qvl::QuoteCollateralV3, now_secs: u64) -> bool {
    let tcb_info_json: serde_json::Value = match serde_json::from_str(&collateral.tcb_info) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let next_update = tcb_info_json
        .get("nextUpdate")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let parsed = time::OffsetDateTime::parse(next_update, &time::format_description::well_known::Rfc3339);
    match parsed {
        Ok(dt) => now_secs <= dt.unix_timestamp().max(0) as u64,
        Err(_) => false,
    }
}

async fn get_collateral_cached(
    pccs_url: Option<&str>,
    quote: &[u8],
    cache_dir: &Path,
) -> Result<::dcap_qvl::QuoteCollateralV3> {
    let pccs_url = pccs_url
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_PCS_URL);
    if cache_disabled() {
        return ::dcap_qvl::collateral::get_collateral(pccs_url, quote).await;
    }

    let quote_obj = ::dcap_qvl::quote::Quote::parse(quote).context("parse quote")?;
    let ca = quote_obj.ca().context("get CA")?;
    let fmspc = hex::encode_upper(quote_obj.fmspc().context("get FMSPC")?);
    let tee = if quote_obj.header.is_sgx() { "sgx" } else { "tdx" };
    let base_url = normalize_base_url(pccs_url);

    let cache_path: PathBuf = cache_dir.join(cache_key(&base_url, tee, &fmspc, ca));
    let now = now_secs();
    if let Some(cached) = read_cache(&cache_path) {
        if cached_collateral_is_fresh(&cached, now) {
            return Ok(cached);
        }
    }

    let collateral = ::dcap_qvl::collateral::get_collateral(pccs_url, quote).await?;
    write_cache(&cache_path, &collateral)?;
    Ok(collateral)
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
    let parsed = time::OffsetDateTime::parse(next_update, &time::format_description::well_known::Rfc3339).ok()?;
    Some(parsed.unix_timestamp().max(0) as u64)
}

fn collateral_expired(collateral: &::dcap_qvl::QuoteCollateralV3, now: u64) -> bool {
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

pub async fn ecdsa_quote_verification_with_timing(
    quote: &[u8],
) -> Result<(Map<String, Value>, f64)> {
    let pccs_url = std::env::var("PCCS_URL").ok();
    let cache_dir = std::env::var("DCAP_QVL_CACHE_DIR").unwrap_or_else(|_| "dcap-qvl-cache".into());
    let collateral_start = Instant::now();
    let collateral = get_collateral_cached(pccs_url.as_deref(), quote, Path::new(&cache_dir))
        .await
        .context("get collateral")?;
    let collateral_ms = collateral_start.elapsed().as_secs_f64() * 1000.0;

    let now = now_secs();
    // Match Intel DCAP behavior: treat expired collateral as a warning.
    if std::env::var("DCAP_QVL_IGNORE_EXPIRY").is_err() {
        std::env::set_var("DCAP_QVL_IGNORE_EXPIRY", "1");
    }
    // Allow non-zero MR_SERVICETD for TDX 1.5 quotes (service TD bound).
    if std::env::var("DCAP_QVL_ALLOW_SERVICE_TD").is_err() {
        std::env::set_var("DCAP_QVL_ALLOW_SERVICE_TD", "1");
    }

    let verified = ::dcap_qvl::verify::verify(quote, &collateral, now)
        .context("dcap-qvl quote verification failed")?;
    let mut claims = custom_claims_from_verified_report(verified);
    if collateral_expired(&collateral, now) {
        claims.insert("collateral_expired".to_string(), Value::Bool(true));
    }
    Ok((claims, collateral_ms))
}
