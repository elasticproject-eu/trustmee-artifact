//! Paper-evaluation JSON timing emitter.
//!
//! Emits single-line JSON events to stderr, gated on env vars so default
//! builds are unaffected. Consumers (paper-evaluation/bin/parse_timings.py)
//! read these lines from the AS log.

use serde_json::{json, Value};
use std::io::Write;

const ENV_VERIFIER_TIMING: &str = "AS_VERIFICATION_TIMING_JSON";
const ENV_SNP_STEP_TIMING: &str = "SNP_STEP_TIMING_JSON";
const ENV_TDX_COLLATERAL_TIMING: &str = "AS_VERIFICATION_TIMING_JSON";

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

pub fn verifier_timing_enabled() -> bool {
    env_flag(ENV_VERIFIER_TIMING)
}

pub fn snp_step_timing_enabled() -> bool {
    env_flag(ENV_SNP_STEP_TIMING)
}

pub fn tdx_collateral_timing_enabled() -> bool {
    env_flag(ENV_TDX_COLLATERAL_TIMING)
}

fn emit(event: &str, fields: &[(&str, Value)]) {
    let mut obj = serde_json::Map::new();
    obj.insert("event".to_string(), Value::String(event.to_string()));
    for (k, v) in fields {
        obj.insert((*k).to_string(), v.clone());
    }
    let line = Value::Object(obj).to_string();
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}

pub fn emit_as_verifier_timing(tee: &str, mode: &str, ms: f64) {
    if !verifier_timing_enabled() {
        return;
    }
    emit(
        "as_verifier_timing",
        &[
            ("tee", Value::String(tee.to_string())),
            ("mode", Value::String(mode.to_string())),
            ("ms", json!(ms)),
        ],
    );
}

pub fn emit_snp_step_timing(
    mode: &str,
    cert_chain_ms: f64,
    signature_ms: f64,
    others_ms: f64,
    total_ms: f64,
) {
    if !snp_step_timing_enabled() {
        return;
    }
    emit(
        "snp_step_timing",
        &[
            ("mode", Value::String(mode.to_string())),
            ("cert_chain_ms", json!(cert_chain_ms)),
            ("signature_ms", json!(signature_ms)),
            ("others_ms", json!(others_ms)),
            ("total_ms", json!(total_ms)),
        ],
    );
}

pub fn emit_tdx_collateral_timing(mode: &str, ms: f64) {
    if !tdx_collateral_timing_enabled() {
        return;
    }
    emit(
        "as_tdx_collateral_timing",
        &[
            ("tee", Value::String("Tdx".to_string())),
            ("mode", Value::String(mode.to_string())),
            ("ms", json!(ms)),
        ],
    );
}

/// Helper: milliseconds between two Instants, as f64.
pub fn ms_since(start: std::time::Instant) -> f64 {
    let d = start.elapsed();
    d.as_secs_f64() * 1000.0
}
