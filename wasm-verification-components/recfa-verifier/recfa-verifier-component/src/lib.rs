//! ReCFA control-flow attestation verifier, as a TrustMee Wasm verification
//! component.
//!
//! The verification logic is upstream ReCFA's `src/verifier/check.cpp`, vendored
//! under `vendor/` and compiled to `wasm32-wasip2` essentially unmodified (see
//! `vendor/patch-upstream.py` for the exact, asserted diff). This file is only
//! the WIT glue: it validates the inputs, hands them to the C++ verifier through
//! an in-memory buffer registry, and turns the verdict into claims.
//!
//! Evidence  : the folded control-flow event stream produced by the attester
//!             (`*_instru-re_folded`), a sequence of little-endian u32 events.
//! Endorsements (reference values, see README for the full table):
//!   recfa-disassembly  objdump -d output of the attested binary
//!   recfa-cfg          preCFG (Dyninst ParseAPI) .dot control-flow graph
//!   recfa-policy-f     patched-typearmor binfo (legal indirect-call targets)
//!   recfa-policy-m     csfilter .filtered.map (skipped direct call sites)
//!   recfa-config       JSON: {"compiler_type":"gcc"|"llvm","num_executions":N}

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

wit_bindgen::generate!({
    path: "wit",
    world: "recfa-verifier",
});

use exports::trustee::verifier::verifier_interface as iface;

// ---------------------------------------------------------------------------
// FFI to the vendored ReCFA verifier. Mirrors vendor/recfa_entry.h exactly.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RecfaResult {
    events_attested: i64,
    events_unprocessed: i64,
    events_reconstructed: i64,
    verdict: i32,
    policy_m_entries: u32,
    policy_f_entries: u32,
    violation_site: u32,
    violation_target: u32,
    main_addr: u32,
    main_ret_addr: u32,
}

extern "C" {
    fn recfa_vfs_put(name: *const u8, data: *const u8, len: core::ffi::c_ulong);
    fn recfa_vfs_clear();
    fn recfa_verify(
        asm_name: *const u8,
        dot_name: *const u8,
        f_name: *const u8,
        m_name: *const u8,
        trace_name: *const u8,
        num_executions: i32,
        compiler_type: *const u8,
        out: *mut RecfaResult,
    ) -> i32;
}

const V_UNKNOWN: i32 = 0;
const V_SECURE: i32 = 1;
const V_SHADOW: i32 = 2;
const V_ICALL: i32 = 3;
const V_IJMP: i32 = 4;
const V_DYNINST: i32 = 5;
const V_POLICY_F: i32 = 6;

// Names used as VFS keys; must be NUL-terminated for the C side.
const N_ASM: &[u8] = b"recfa.asm\0";
const N_DOT: &[u8] = b"recfa.dot\0";
const N_F: &[u8] = b"recfa.policy-f\0";
const N_M: &[u8] = b"recfa.policy-m\0";
const N_TRACE: &[u8] = b"recfa.trace\0";

// ---------------------------------------------------------------------------
// Endorsement labels
// ---------------------------------------------------------------------------

const L_ASM: &str = "recfa-disassembly";
const L_DOT: &str = "recfa-cfg";
const L_F: &str = "recfa-policy-f";
const L_M: &str = "recfa-policy-m";
const L_CONFIG: &str = "recfa-config";

// ---------------------------------------------------------------------------
// Input limits.
//
// The vendored C++ is built with -fno-exceptions, so an allocation failure or a
// pathological std::regex input would abort rather than unwind, and an abort is
// a host-level trap rather than a verdict. We therefore bound the inputs here,
// in safe Rust, before the C++ ever sees them.
// ---------------------------------------------------------------------------

const MAX_TEXT: usize = 256 * 1024 * 1024;
const MAX_EVIDENCE: usize = 512 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;
const MAX_EXECUTIONS: i64 = 4096;

fn failure(msg: impl Into<String>) -> Value {
    json!({ "status": "failed", "error": msg.into() })
}

fn find_endorsement<'a>(input: &'a iface::VerifierInput, label: &str) -> Result<&'a [u8], Value> {
    let mut m = input
        .endorsements
        .iter()
        .filter(|e| e.label == label)
        .map(|e| e.payload.as_slice());
    let first = m
        .next()
        .ok_or_else(|| failure(format!("missing required endorsement `{label}`")))?;
    if m.next().is_some() {
        return Err(failure(format!("duplicate endorsement `{label}`")));
    }
    Ok(first)
}

fn find_optional<'a>(
    input: &'a iface::VerifierInput,
    label: &str,
) -> Result<Option<&'a [u8]>, Value> {
    let mut m = input
        .endorsements
        .iter()
        .filter(|e| e.label == label)
        .map(|e| e.payload.as_slice());
    let first = match m.next() {
        Some(p) => p,
        None => return Ok(None),
    };
    if m.next().is_some() {
        return Err(failure(format!("duplicate endorsement `{label}`")));
    }
    Ok(Some(first))
}

/// Reject text reference data that could make the C++ regex engine misbehave.
fn check_text(bytes: &[u8], what: &str) -> Result<(), Value> {
    if bytes.len() > MAX_TEXT {
        return Err(failure(format!(
            "{what} too large: {} bytes (limit {MAX_TEXT})",
            bytes.len()
        )));
    }
    if bytes.contains(&0) {
        return Err(failure(format!("{what} contains a NUL byte")));
    }
    let mut line = 0usize;
    for &b in bytes {
        if b == b'\n' {
            line = 0;
        } else {
            line += 1;
            if line > MAX_LINE {
                return Err(failure(format!(
                    "{what} has a line longer than {MAX_LINE} bytes"
                )));
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// ReCFA evidence has no REPORT_DATA field of its own, so when the host supplies
/// an expected value we bind it to the digest of the event stream: the first 32
/// bytes must be sha256(evidence) and any remainder must be zero padding. That
/// lets a caller (or an enclosing TEE quote) commit to exactly this trace.
fn check_report_data(expected: &[u8], evidence_digest_hex: &str) -> Result<(), Value> {
    if expected.len() < 32 {
        return Err(failure(format!(
            "expected report data is {} bytes, need at least 32 to bind sha256(evidence)",
            expected.len()
        )));
    }
    let want = hex::decode(evidence_digest_hex).unwrap_or_default();
    if expected[..32] != want[..] {
        return Err(failure(
            "expected report data does not match sha256(evidence): \
             the event stream is not the one that was committed to"
                .to_string(),
        ));
    }
    if expected[32..].iter().any(|b| *b != 0) {
        return Err(failure(
            "expected report data has non-zero bytes after the 32-byte digest".to_string(),
        ));
    }
    Ok(())
}

fn verdict_name(v: i32) -> &'static str {
    match v {
        V_SECURE => "secure",
        V_SHADOW => "shadow-stack-violation",
        V_ICALL => "indirect-call-violation",
        V_IJMP => "indirect-jump-violation",
        V_DYNINST => "cfg-policy-m-inconsistent",
        V_POLICY_F => "policy-f-inconsistent",
        _ => "unknown",
    }
}

fn evaluate_impl(
    input: &iface::VerifierInput,
    expected_report_data: &iface::OptionalData,
    expected_init_data_hash: &iface::OptionalData,
) -> Result<Value, Value> {
    // ReCFA has no init-data register (no MRCONFIGID/HOSTDATA analogue). Fail
    // closed rather than silently ignoring a binding the caller asked for.
    if let iface::OptionalData::Value(_) = expected_init_data_hash {
        return Err(failure(
            "expected-init-data-hash was provided, but ReCFA evidence has no \
             init-data measurement to bind it to; compose this component under a \
             TEE verifier if you need that binding",
        ));
    }

    // --- evidence -------------------------------------------------------
    let evidence = input.evidence.as_slice();
    if evidence.is_empty() {
        return Err(failure("evidence is empty"));
    }
    if evidence.len() > MAX_EVIDENCE {
        return Err(failure(format!(
            "evidence too large: {} bytes (limit {MAX_EVIDENCE})",
            evidence.len()
        )));
    }
    let media = input.evidence_media_type.as_str();
    if !(media.is_empty()
        || media == "application/octet-stream"
        || media == "application/vnd.recfa.folded-events")
    {
        return Err(failure(format!(
            "unsupported evidence media type `{media}`; expected \
             application/octet-stream"
        )));
    }

    // --- reference values ------------------------------------------------
    let asm = find_endorsement(input, L_ASM)?;
    check_text(asm, "disassembly")?;
    let dot = find_endorsement(input, L_DOT)?;
    check_text(dot, "cfg")?;
    let policy_f = find_endorsement(input, L_F)?;
    check_text(policy_f, "policy F")?;
    let policy_m = find_optional(input, L_M)?.unwrap_or(&[]);
    check_text(policy_m, "policy M")?;

    let config = find_endorsement(input, L_CONFIG)?;
    check_text(config, "config")?;
    let config: Value = serde_json::from_slice(config)
        .map_err(|e| failure(format!("endorsement `{L_CONFIG}` is not valid JSON: {e}")))?;

    let compiler = config
        .get("compiler_type")
        .and_then(Value::as_str)
        .ok_or_else(|| failure(format!("`{L_CONFIG}` is missing string `compiler_type`")))?;
    // This is not cosmetic: it selects which register the indirect-jump regex
    // matches (gcc -> %rax, llvm -> %rcx), so the wrong value silently loses
    // every indirect jump.
    if compiler != "gcc" && compiler != "llvm" {
        return Err(failure(format!(
            "`compiler_type` must be \"gcc\" or \"llvm\", got \"{compiler}\""
        )));
    }
    let num_executions = config
        .get("num_executions")
        .map(|v| {
            v.as_i64()
                .ok_or_else(|| failure("`num_executions` must be an integer"))
        })
        .transpose()?
        .unwrap_or(1);
    if num_executions < 1 || num_executions > MAX_EXECUTIONS {
        return Err(failure(format!(
            "`num_executions` must be in 1..={MAX_EXECUTIONS}, got {num_executions}"
        )));
    }

    // --- bind the caller's expected report data, if any -------------------
    let evidence_sha256 = sha256_hex(evidence);
    let report_data_bound = match expected_report_data {
        iface::OptionalData::Value(v) => {
            check_report_data(v, &evidence_sha256)?;
            true
        }
        iface::OptionalData::NotProvided => false,
    };

    // --- run the vendored verifier ---------------------------------------
    let mut out = RecfaResult::default();
    let mut compiler_c = compiler.as_bytes().to_vec();
    compiler_c.push(0);

    let rc = unsafe {
        recfa_vfs_clear();
        recfa_vfs_put(N_ASM.as_ptr(), asm.as_ptr(), asm.len() as _);
        recfa_vfs_put(N_DOT.as_ptr(), dot.as_ptr(), dot.len() as _);
        recfa_vfs_put(N_F.as_ptr(), policy_f.as_ptr(), policy_f.len() as _);
        recfa_vfs_put(N_M.as_ptr(), policy_m.as_ptr(), policy_m.len() as _);
        recfa_vfs_put(N_TRACE.as_ptr(), evidence.as_ptr(), evidence.len() as _);
        let rc = recfa_verify(
            N_ASM.as_ptr(),
            N_DOT.as_ptr(),
            N_F.as_ptr(),
            N_M.as_ptr(),
            N_TRACE.as_ptr(),
            num_executions as i32,
            compiler_c.as_ptr(),
            &mut out as *mut RecfaResult,
        );
        recfa_vfs_clear();
        rc
    };

    // Facts a Trustee policy can appraise, emitted for success and failure alike.
    let diagnostics = json!({
        "verdict": verdict_name(out.verdict),
        "events_attested": out.events_attested,
        "events_reconstructed": out.events_reconstructed,
        "events_unprocessed": out.events_unprocessed,
        "policy_f_call_sites": out.policy_f_entries,
        "policy_m_entries": out.policy_m_entries,
        "compiler_type": compiler,
        "num_executions": num_executions,
        "main_addr": format!("{:#x}", out.main_addr),
        "main_ret_addr": format!("{:#x}", out.main_ret_addr),
        "evidence_bytes": evidence.len(),
        "evidence_events": evidence.len() / 4,
    });

    if rc != 0 && out.verdict == V_UNKNOWN {
        let mut v = failure("ReCFA verifier rejected the inputs before verification");
        v["recfa"] = diagnostics;
        return Err(v);
    }

    if out.verdict != V_SECURE {
        let detail = match out.verdict {
            V_ICALL | V_IJMP => format!(
                "{} at {:#x}: target {:#x} is not permitted",
                verdict_name(out.verdict),
                out.violation_site,
                out.violation_target
            ),
            V_SHADOW => format!(
                "shadow-stack violation: return address mismatch, {} events left unprocessed",
                out.events_unprocessed
            ),
            V_DYNINST => "policy M refers to a call site the CFG does not describe \
                          (mismatched .dot / .filtered.map for this binary)"
                .to_string(),
            V_POLICY_F => "policy F refers to a call site absent from the disassembly \
                           (mismatched binfo / .asm for this binary)"
                .to_string(),
            _ => "ReCFA verifier produced no verdict".to_string(),
        };
        let mut v = failure(detail);
        v["recfa"] = diagnostics;
        return Err(v);
    }

    Ok(json!({
        "attester_type": "recfa",
        "recfa": diagnostics,
        "evidence_sha256": evidence_sha256,
        "report_data_bound": report_data_bound,
        "reference_values": {
            "disassembly_sha256": sha256_hex(asm),
            "cfg_sha256": sha256_hex(dot),
            "policy_f_sha256": sha256_hex(policy_f),
            "policy_m_sha256": sha256_hex(policy_m),
        },
        // ReCFA's own threat model puts the trust anchor outside the scheme; make
        // that explicit so a policy cannot mistake this for a hardware verdict.
        "hardware_rooted": false,
    }))
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
        expected_report_data: iface::OptionalData,
        expected_init_data_hash: iface::OptionalData,
    ) -> String {
        let v = match evaluate_impl(&input, &expected_report_data, &expected_init_data_hash) {
            Ok(v) => v,
            Err(v) => v,
        };
        // Never panic: a serialisation failure still has to come back as a verdict.
        serde_json::to_string(&v).unwrap_or_else(|e| {
            format!("{{\"status\":\"failed\",\"error\":\"claims serialisation failed: {e}\"}}")
        })
    }
}

export!(Component);
