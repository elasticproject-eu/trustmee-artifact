use anyhow::{Context, Result};
use ::dcap_qvl::verify::VerifiedReport;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;
use tokio::time::sleep;

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

struct RetrySettings {
    max_retries: u32,
    initial_delay: Duration,
    backoff: f64,
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .unwrap_or(default)
}

fn collateral_retry_settings() -> RetrySettings {
    let max_retries = env_u64("TDX_DCAP_QVL_RETRY_MAX", 0) as u32;
    let initial_delay =
        Duration::from_secs_f64(env_f64("TDX_DCAP_QVL_RETRY_INITIAL_SECS", 0.0).max(0.0));
    let backoff = env_f64("TDX_DCAP_QVL_RETRY_BACKOFF", 1.0).max(1.0);
    RetrySettings {
        max_retries,
        initial_delay,
        backoff,
    }
}

fn collateral_min_interval() -> Duration {
    Duration::from_secs_f64(
        env_f64("TDX_DCAP_QVL_REQUEST_INTERVAL_SECS", 0.0).max(0.0),
    )
}

static LAST_COLLATERAL_FETCH: OnceLock<Mutex<Instant>> = OnceLock::new();

async fn throttle_collateral_requests(min_interval: Duration) {
    if min_interval == Duration::ZERO {
        return;
    }
    let initial = Instant::now()
        .checked_sub(min_interval)
        .unwrap_or_else(Instant::now);
    let lock = LAST_COLLATERAL_FETCH.get_or_init(|| Mutex::new(initial));
    let now = Instant::now();
    let mut last = lock.lock().await;
    let next_allowed = (*last + min_interval).max(now);
    let wait = next_allowed.saturating_duration_since(now);
    *last = next_allowed;
    drop(last);
    if wait != Duration::ZERO {
        sleep(wait).await;
    }
}

async fn get_collateral_with_backoff(
    pccs_url: &str,
    quote: &[u8],
) -> Result<::dcap_qvl::QuoteCollateralV3> {
    let settings = collateral_retry_settings();
    let min_interval = collateral_min_interval();
    let mut attempt = 0u32;
    let mut delay = settings.initial_delay;

    loop {
        throttle_collateral_requests(min_interval).await;
        match ::dcap_qvl::collateral::get_collateral(pccs_url, quote).await {
            Ok(collateral) => return Ok(collateral),
            Err(err) => {
                if attempt >= settings.max_retries {
                    return Err(err).context("get collateral");
                }
                attempt += 1;
                if delay != Duration::ZERO {
                    sleep(delay).await;
                }
                if settings.backoff > 1.0 {
                    delay = Duration::from_secs_f64(delay.as_secs_f64() * settings.backoff);
                }
            }
        }
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
        return get_collateral_with_backoff(pccs_url, quote).await;
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

    let collateral = get_collateral_with_backoff(pccs_url, quote).await?;
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
    let cache_dir = PathBuf::from(cache_dir);
    let collateral_start = Instant::now();
    let collateral = get_collateral_cached(pccs_url.as_deref(), quote, cache_dir.as_path())
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
