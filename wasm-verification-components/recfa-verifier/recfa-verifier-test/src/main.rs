//! Local harness for the ReCFA verification component.
//!
//! Instantiates the component in wasmtime, assembles the ReCFA reference values
//! as endorsements, feeds the folded control-flow event stream as evidence, and
//! prints the returned claims.
//!
//! Example (fixture shipped in ../test_data):
//!
//!   cargo run -p recfa-verifier-test -- \
//!     --component ../../target/wasm32-wasip2/release/recfa_verifier_component.wasm \
//!     --disassembly ../test_data/prog.asm \
//!     --cfg         ../test_data/prog.dot \
//!     --policy-f    ../test_data/binfo.prog \
//!     --policy-m    ../test_data/pass_simple.map \
//!     --trace       ../test_data/pass_simple.trace \
//!     --compiler gcc
//!
//! `--expect secure|failed` makes it usable as a test assertion, and
//! `--batch <dir>` runs every `*.trace` in a directory, inferring the expected
//! outcome from the `pass_`/`fail_` filename prefix.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Store};
use wasmtime_wasi::p2::{IoView, WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!({
    path: "../recfa-verifier-component/wit",
    world: "recfa-verifier",
});

use exports::trustee::verifier::verifier_interface as iface;

#[derive(Parser, Debug)]
#[command(name = "recfa-verifier-test")]
struct Args {
    /// Wasm component built for wasm32-wasip2.
    #[arg(long)]
    component: PathBuf,

    /// objdump -d output for the attested binary (binutils <= 2.34).
    #[arg(long)]
    disassembly: PathBuf,

    /// preCFG .dot control-flow graph.
    #[arg(long)]
    cfg: PathBuf,

    /// Policy F: patched-typearmor binfo file.
    #[arg(long)]
    policy_f: PathBuf,

    /// Policy M: csfilter .filtered.map file (optional).
    #[arg(long)]
    policy_m: Option<PathBuf>,

    /// Folded control-flow event stream (the evidence).
    #[arg(long, required_unless_present = "batch")]
    trace: Option<PathBuf>,

    /// Run every *.trace in this directory; pass_*/fail_* set the expectation.
    #[arg(long)]
    batch: Option<PathBuf>,

    #[arg(long, default_value = "gcc")]
    compiler: String,

    #[arg(long, default_value_t = 1)]
    num_executions: i64,

    /// Bind the evidence: sends sha256(trace) as expected report data.
    #[arg(long)]
    bind_report_data: bool,

    /// Send a deliberately wrong report data, to check the binding fails closed.
    #[arg(long, conflicts_with = "bind_report_data")]
    bind_wrong_report_data: bool,

    /// Assert the outcome: "secure" or "failed".
    #[arg(long)]
    expect: Option<String>,

    /// Base cache dir; a fresh subdir is preopened to the guest as `cache/`.
    #[arg(long, default_value = ".recfa-verifier-cache")]
    cache_dir: PathBuf,
}

static CACHE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_cache_dir(base: &Path) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!(
        "recfa-verifier-cache-{nanos:x}-{}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
}

impl HostState {
    fn new(cache_dir: &Path) -> Result<Self> {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        use wasmtime_wasi::{DirPerms, FilePerms};
        // The component does not actually need the filesystem (inputs are passed
        // in memory), but we preopen cache/ to match how the host runs it.
        wasi.preopened_dir(cache_dir, "cache", DirPerms::all(), FilePerms::all())
            .with_context(|| format!("preopen {}", cache_dir.display()))?;
        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
        })
    }
}

impl IoView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}
impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().to_vec()
}

struct Inputs {
    asm: Vec<u8>,
    cfg: Vec<u8>,
    policy_f: Vec<u8>,
    policy_m: Vec<u8>,
    config: Vec<u8>,
}

fn endorsements(i: &Inputs) -> Vec<iface::Endorsement> {
    let mk = |label: &str, media: &str, payload: &[u8]| iface::Endorsement {
        label: label.to_string(),
        media_type: media.to_string(),
        payload: payload.to_vec(),
    };
    vec![
        mk("recfa-disassembly", "text/plain", &i.asm),
        mk("recfa-cfg", "text/vnd.graphviz", &i.cfg),
        mk("recfa-policy-f", "text/plain", &i.policy_f),
        mk("recfa-policy-m", "text/plain", &i.policy_m),
        mk("recfa-config", "application/json", &i.config),
    ]
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    engine: &wasmtime::Engine,
    component: &Component,
    linker: &Linker<HostState>,
    cache_base: &Path,
    inputs: &Inputs,
    trace: &[u8],
    report_data: iface::OptionalData,
) -> Result<serde_json::Value> {
    let cache_dir = unique_cache_dir(cache_base)?;
    let state = HostState::new(&cache_dir)?;
    let mut store = Store::new(engine, state);

    let bindings = RecfaVerifier::instantiate(&mut store, component, linker)?;
    let vi = bindings.trustee_verifier_verifier_interface();
    let verifier = vi.verifier();
    let res = verifier.call_constructor(&mut store)?;

    let input = iface::VerifierInput {
        evidence: trace.to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        endorsements: endorsements(inputs),
    };

    let out = verifier.call_evaluate(
        &mut store,
        res,
        &input,
        &report_data,
        &iface::OptionalData::NotProvided,
    )?;
    serde_json::from_str(&out).context("component returned non-JSON")
}

fn main() -> Result<()> {
    let args = Args::parse();

    let inputs = Inputs {
        asm: std::fs::read(&args.disassembly)
            .with_context(|| format!("read {}", args.disassembly.display()))?,
        cfg: std::fs::read(&args.cfg).with_context(|| format!("read {}", args.cfg.display()))?,
        policy_f: std::fs::read(&args.policy_f)
            .with_context(|| format!("read {}", args.policy_f.display()))?,
        policy_m: match args.policy_m.as_ref() {
            Some(p) => std::fs::read(p).with_context(|| format!("read {}", p.display()))?,
            None => Vec::new(),
        },
        config: serde_json::to_vec(&serde_json::json!({
            "compiler_type": args.compiler,
            "num_executions": args.num_executions,
        }))?,
    };

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = wasmtime::Engine::new(&config)?;
    let component = Component::from_file(&engine, &args.component)
        .with_context(|| format!("load component {}", args.component.display()))?;
    let mut linker = Linker::<HostState>::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;

    // ---- batch mode ----------------------------------------------------
    if let Some(dir) = args.batch.as_ref() {
        let mut cases: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("read dir {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|e| e == "trace").unwrap_or(false))
            .collect();
        cases.sort();
        if cases.is_empty() {
            bail!("no *.trace files in {}", dir.display());
        }

        let mut failures = 0;
        println!(
            "{:<18} {:<26} {:<8} {}",
            "CASE", "VERDICT", "EVENTS", "RESULT"
        );
        for case in &cases {
            let stem = case
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow!("bad filename"))?
                .to_string();
            let trace = std::fs::read(case)?;
            // per-case policy M, if the fixture ships one
            let mut per_case = Inputs {
                asm: inputs.asm.clone(),
                cfg: inputs.cfg.clone(),
                policy_f: inputs.policy_f.clone(),
                policy_m: inputs.policy_m.clone(),
                config: inputs.config.clone(),
            };
            let map = case.with_extension("map");
            if map.exists() {
                per_case.policy_m = std::fs::read(&map)?;
            }

            let v = run_one(
                &engine,
                &component,
                &linker,
                &args.cache_dir,
                &per_case,
                &trace,
                iface::OptionalData::NotProvided,
            )?;

            let failed = v.get("error").is_some();
            let verdict = v
                .pointer("/recfa/verdict")
                .and_then(|x| x.as_str())
                .unwrap_or("-")
                .to_string();
            let events = v
                .pointer("/recfa/events_attested")
                .and_then(|x| x.as_i64())
                .unwrap_or(-1);
            let expect_pass = stem.starts_with("pass_");
            let ok = expect_pass != failed;
            if !ok {
                failures += 1;
            }
            println!(
                "{:<18} {:<26} {:<8} {}",
                stem,
                verdict,
                events,
                if ok {
                    "OK".to_string()
                } else {
                    format!(
                        "UNEXPECTED (expected {}, got {})",
                        if expect_pass { "pass" } else { "fail" },
                        if failed { "fail" } else { "pass" }
                    )
                }
            );
            if !ok {
                println!("    {v}");
            }
        }
        println!();
        if failures > 0 {
            bail!("{failures} of {} cases behaved unexpectedly", cases.len());
        }
        println!("PASS: all {} cases behaved as expected", cases.len());
        return Ok(());
    }

    // ---- single case ---------------------------------------------------
    let trace_path = args
        .trace
        .as_ref()
        .ok_or_else(|| anyhow!("--trace is required unless --batch is used"))?;
    let trace =
        std::fs::read(trace_path).with_context(|| format!("read {}", trace_path.display()))?;

    let report_data = if args.bind_report_data {
        let mut rd = sha256(&trace);
        rd.resize(64, 0);
        iface::OptionalData::Value(rd)
    } else if args.bind_wrong_report_data {
        iface::OptionalData::Value(vec![0xAB; 64])
    } else {
        iface::OptionalData::NotProvided
    };

    let value = run_one(
        &engine,
        &component,
        &linker,
        &args.cache_dir,
        &inputs,
        &trace,
        report_data,
    )?;

    println!("{}", serde_json::to_string_pretty(&value)?);

    let failed = value.get("error").is_some();
    if let Some(expect) = args.expect.as_deref() {
        match expect {
            "secure" if failed => bail!("expected secure, but verification failed"),
            "failed" if !failed => bail!("expected failure, but verification succeeded"),
            "secure" | "failed" => {}
            other => bail!("--expect must be \"secure\" or \"failed\", got {other:?}"),
        }
        println!("(expectation `{expect}` met)");
        return Ok(());
    }

    if failed {
        return Err(anyhow!("attestation failed"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// End-to-end tests over the custom-binary example in ../custom-e2e.
//
// The artifacts there are not hand-written: prog.c is compiled non-PIE, policy F
// comes from the patched typearmor pass, policy M from csfilter, the CFG from
// Dyninst preCFG, and the evidence is the folded event stream of a real run of
// the statically instrumented binary. `custom-e2e/build.sh` regenerates all of
// it; these tests only consume what is committed.
//
// Both tests drive the **Wasm component** through wasmtime — never upstream's
// native `check` — so they need the component built:
//
//   bash ../custom-e2e/build.sh --test-only
//   # or: cargo test -p recfa-verifier-test -- --ignored custom_e2e
//
// Expectations are derived from the artifacts themselves (digests, the policy-F
// site table, the one event make-tamper.py changed) rather than hardcoded, so
// regenerating the example cannot silently invalidate them.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod custom_e2e {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Pinned to document the committed evidence. The attested count exceeds the
    /// event count because verification re-expands what the attester folded away:
    /// the loop iterations, plus the two direct call sites csfilter told the
    /// attester to skip and policy M puts back.
    const EVIDENCE_EVENTS: i64 = 24;
    const ATTESTED_ADDRESSES: i64 = 29;
    const RECONSTRUCTED_ADDRESSES: i64 = 2;

    fn example_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../custom-e2e/artifacts")
    }

    fn artifact(name: &str) -> Vec<u8> {
        let path = example_dir().join(name);
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "read {}: {e}\nrun `bash recfa-verifier/custom-e2e/build.sh` first",
                path.display()
            )
        })
    }

    fn inputs() -> Inputs {
        Inputs {
            asm: artifact("prog.asm"),
            cfg: artifact("prog.dot"),
            policy_f: artifact("binfo.prog"),
            policy_m: artifact("prog.filtered.map"),
            config: serde_json::to_vec(&serde_json::json!({
                "compiler_type": "gcc",
                "num_executions": 1,
            }))
            .unwrap(),
        }
    }

    /// Runs the component over one trace and returns its claims.
    fn evaluate(trace: &[u8]) -> serde_json::Value {
        let component_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-wasip2/release/recfa_verifier_component.wasm");
        assert!(
            component_path.exists(),
            "component missing: {}\nbuild it with `WASI_SDK_PATH=… cargo build \
             -p recfa-verifier-component --release --target wasm32-wasip2`",
            component_path.display()
        );

        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine");
        let component = Component::from_file(&engine, &component_path).expect("load component");
        let mut linker = Linker::<HostState>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).expect("link wasi");

        let cache_base =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.recfa-verifier-cache");
        run_one(
            &engine,
            &component,
            &linker,
            &cache_base,
            &inputs(),
            trace,
            iface::OptionalData::NotProvided,
        )
        .expect("evaluate")
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        hex::encode(sha256(bytes))
    }

    fn events(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// Parse policy F into site -> permitted targets. Line format, as emitted by
    /// the patched typearmor pass and consumed by the verifier:
    ///   `Indirectstar0x<site>  <argc> Indirectend0x<target> <argc>`
    fn policy_f() -> BTreeMap<u32, BTreeSet<u32>> {
        let text = String::from_utf8(artifact("binfo.prog")).expect("policy F is text");
        let mut map: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for line in text.lines() {
            let Some(rest) = line.split_once("Indirectstar0x").map(|(_, r)| r) else {
                continue;
            };
            let Some((site, rest)) = rest.split_once(' ') else {
                continue;
            };
            let Some(target) = rest
                .split_once("Indirectend0x")
                .and_then(|(_, t)| t.split_whitespace().next())
            else {
                continue;
            };
            let (Ok(site), Ok(target)) = (
                u32::from_str_radix(site, 16),
                u32::from_str_radix(target, 16),
            ) else {
                continue;
            };
            map.entry(site).or_default().insert(target);
        }
        assert!(!map.is_empty(), "policy F has no Indirectstar entries");
        map
    }

    /// The real run of the instrumented binary verifies, and the claims describe
    /// exactly the reference values that were committed.
    #[test]
    #[ignore = "requires recfa_verifier_component.wasm; see custom-e2e/build.sh --test"]
    fn clean_trace_verifies_secure() {
        let trace = artifact("prog_instru-re_folded");
        let claims = evaluate(&trace);

        assert!(
            claims.get("error").is_none(),
            "verification of the untampered trace failed: {claims}"
        );
        assert_eq!(claims["recfa"]["verdict"], serde_json::json!("secure"));
        assert_eq!(claims["recfa"]["events_unprocessed"], serde_json::json!(0));
        assert_eq!(claims["attester_type"], serde_json::json!("recfa"));
        // ReCFA is not a TEE scheme; the component must keep saying so.
        assert_eq!(claims["hardware_rooted"], serde_json::json!(false));

        assert_eq!(
            claims["recfa"]["evidence_events"],
            serde_json::json!(EVIDENCE_EVENTS),
            "folded evidence changed size"
        );
        assert_eq!(
            claims["recfa"]["events_attested"],
            serde_json::json!(ATTESTED_ADDRESSES),
            "attested address count changed"
        );
        // Non-zero only because policy M is in play: csfilter told the attester to
        // skip two direct call sites, and the verifier puts them back.
        assert_eq!(
            claims["recfa"]["events_reconstructed"],
            serde_json::json!(RECONSTRUCTED_ADDRESSES),
            "policy-M call-site reconstruction changed"
        );
        assert_eq!(
            claims["recfa"]["policy_m_entries"],
            serde_json::json!(String::from_utf8_lossy(&artifact("prog.filtered.map"))
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count() as i64),
            "component's |M| disagrees with prog.filtered.map"
        );

        // |F| is the component's call-site table, built from every `callq` line in
        // the disassembly — the number upstream prints as |F|. Cross-checking it
        // catches the silent binutils >= 2.35 failure, where no call site is
        // matched at all and every trace trivially passes.
        let call_sites = String::from_utf8_lossy(&artifact("prog.asm"))
            .lines()
            .filter(|l| l.contains("callq"))
            .count() as i64;
        assert!(
            call_sites > 0,
            "no callq lines in the committed disassembly"
        );
        assert_eq!(
            claims["recfa"]["policy_f_call_sites"],
            serde_json::json!(call_sites),
            "component's |F| disagrees with the callq sites in prog.asm"
        );

        // The digests pin the verdict to these exact reference values.
        assert_eq!(
            claims["evidence_sha256"],
            serde_json::json!(hex_sha256(&trace))
        );
        let refs = &claims["reference_values"];
        assert_eq!(
            refs["disassembly_sha256"],
            serde_json::json!(hex_sha256(&artifact("prog.asm")))
        );
        assert_eq!(
            refs["cfg_sha256"],
            serde_json::json!(hex_sha256(&artifact("prog.dot")))
        );
        assert_eq!(
            refs["policy_f_sha256"],
            serde_json::json!(hex_sha256(&artifact("binfo.prog")))
        );
        assert_eq!(
            refs["policy_m_sha256"],
            serde_json::json!(hex_sha256(&artifact("prog.filtered.map")))
        );
    }

    /// The hijack `tools/make-tamper.py` derives from that same run is rejected,
    /// and the component names the offending edge.
    ///
    /// Only `.tamper_icall` is asserted on. make-tamper.py also writes
    /// `.tamper_ret`, but it corrupts an arbitrary plain event mid-stream, and on
    /// a trace this short that lands on a return *source*; the verifier compares
    /// return *targets* against the shadow stack and never looks at the source, so
    /// that variant legitimately verifies as secure. See custom-e2e/README.md.
    #[test]
    #[ignore = "requires recfa_verifier_component.wasm; see custom-e2e/build.sh --test"]
    fn tampered_trace_is_rejected() {
        let clean = events(&artifact("prog_instru-re_folded"));

        let hijacked_bytes = artifact("prog_instru-re_folded.tamper_icall");
        let hijacked = events(&hijacked_bytes);
        assert_eq!(
            hijacked.len(),
            clean.len(),
            "tamper changed the trace length"
        );
        let changed: Vec<usize> = (0..clean.len())
            .filter(|&i| clean[i] != hijacked[i])
            .collect();
        assert_eq!(
            changed.len(),
            1,
            "expected exactly one changed event: {changed:?}"
        );

        // make-tamper.py rewrites the *target* of a (site, target) pair, so the
        // site is the event before it. Check that this really is a call-site
        // mismatch: a target that policy F permits somewhere, but not here.
        let index = changed[0];
        assert!(index > 0, "the changed event cannot be the first one");
        let site = clean[index - 1];
        let bogus = hijacked[index];
        let policy = policy_f();
        let permitted = policy
            .get(&site)
            .unwrap_or_else(|| panic!("0x{site:06x} is not a policy-F call site"));
        assert!(
            !permitted.contains(&bogus),
            "0x{bogus:06x} is permitted at 0x{site:06x}, so this is not a hijack"
        );
        assert!(
            policy.values().any(|targets| targets.contains(&bogus)),
            "0x{bogus:06x} is not a real function in policy F"
        );

        let claims = evaluate(&hijacked_bytes);
        assert_eq!(
            claims["recfa"]["verdict"],
            serde_json::json!("indirect-call-violation"),
            "hijacked trace was not rejected as an indirect-call violation: {claims}"
        );
        let error = claims["error"].as_str().unwrap_or_default();
        assert!(
            error.contains(&format!("at 0x{site:x}")) && error.contains(&format!("0x{bogus:x}")),
            "error does not name the offending edge 0x{site:06x} -> 0x{bogus:06x}: {error}"
        );
    }
}
