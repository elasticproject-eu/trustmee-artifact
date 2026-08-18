//! Host test harness for the kata-policy verifier component.
//!
//! Runs the composed `kata_policy_stub_verifier_component.wasm` (kata-policy
//! layer plugged with the stub hardware verifier) against fixtures — no live
//! TEE required. The stub's "quote" is a JSON document carrying the hardware
//! claims to return, so each scenario controls the measured
//! MRCONFIGID/HOSTDATA value directly.
//!
//! Subcommands:
//! - `gen-fixtures`: wrap a genpolicy-produced `policy.rego` into a CoCo
//!   init-data TOML, and derive `approved-templates.json` plus a matching
//!   stub evidence file.
//! - `run`: single evaluation with explicit fixture files.
//! - `scenarios`: the (a)-(f) acceptance matrix from the design, derived
//!   from the base fixtures.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Store};
use wasmtime_wasi::p2::{IoView, WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!({
    path: "../stub-hardware-verifier-component/wit",
    world: "verifier",
});

use exports::trustee::verifier::verifier_interface as iface;

#[derive(Parser, Debug)]
#[command(name = "kata-policy-verifier-test")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate init-data / evidence / approved-template fixtures from a
    /// genpolicy-produced policy.rego.
    GenFixtures {
        /// Raw policy.rego as produced by genpolicy.
        #[arg(long)]
        policy: PathBuf,
        /// Output directory (test_data).
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Evaluate the component once with explicit inputs.
    Run {
        #[arg(long)]
        component: PathBuf,
        /// Stub evidence JSON (the fake "quote").
        #[arg(long)]
        evidence_json: PathBuf,
        /// Init-data TOML endorsement.
        #[arg(long)]
        init_data: PathBuf,
        /// Approved template hashes JSON endorsement.
        #[arg(long)]
        approved_templates: PathBuf,
    },
    /// Run the full fixture scenario matrix (a)-(f).
    Scenarios {
        #[arg(long)]
        component: PathBuf,
        /// Directory holding initdata.toml and approved-templates.json.
        #[arg(long)]
        test_data: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Fixture generation
// ---------------------------------------------------------------------------

const AA_TOML: &str = r#"[token_configs]

[token_configs.coco_as]
url = "http://as.example.com:50004"

[token_configs.kbs]
url = "https://kbs.example.com"
"#;

const CDH_TOML: &str = r#"socket = "unix:///run/confidential-containers/cdh.sock"
credentials = []

[kbc]
name = "cc_kbc"
url = "https://kbs.example.com"
"#;

/// Wrap plaintext files into a CoCo init-data TOML document
/// (<https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md>).
fn make_init_data(policy: &str) -> Result<String> {
    for (name, content) in [("aa.toml", AA_TOML), ("cdh.toml", CDH_TOML), ("policy.rego", policy)] {
        if content.contains("'''") {
            bail!("{name} contains `'''`, cannot embed as TOML multi-line literal");
        }
    }
    // TOML multi-line literals trim one leading newline after the opening
    // delimiter, so the embedded content round-trips byte-exactly as long as
    // it ends with its own newline.
    let mut doc = String::new();
    doc.push_str("algorithm = \"sha256\"\nversion = \"0.1.0\"\n\n[data]\n");
    for (name, content) in [("aa.toml", AA_TOML), ("cdh.toml", CDH_TOML), ("policy.rego", policy)] {
        let sep = if content.ends_with('\n') { "" } else { "\n" };
        doc.push_str(&format!("\"{name}\" = '''\n{content}{sep}'''\n\n"));
    }
    Ok(doc)
}

/// Stub evidence whose hardware claims bind the given init-data document.
/// `register_len` emulates the TEE register width: 48 for TDX MRCONFIGID,
/// 32 for SNP HOSTDATA (the digest is left-aligned and zero-padded).
fn make_evidence(init_data: &str, register_len: usize) -> Result<Value> {
    let digest = Sha256::digest(init_data.as_bytes());
    if register_len < digest.len() {
        bail!("register too small for sha256 digest");
    }
    let mut register = vec![0u8; register_len];
    register[..digest.len()].copy_from_slice(&digest);
    Ok(json!({
        "valid": true,
        "claims": {
            "tee": "stub",
            "init_data": hex::encode(register),
            "report_data": "00".repeat(64),
        }
    }))
}

fn template_hash_of(policy: &str) -> Result<String> {
    let structure = kata_policy_core::parse_policy_structure(policy)
        .map_err(|e| anyhow!("base policy.rego failed structural parse: {e}"))?;
    Ok(structure.template_hash)
}

fn gen_fixtures(policy_path: &Path, out_dir: &Path) -> Result<()> {
    let policy = std::fs::read_to_string(policy_path)
        .with_context(|| format!("read {}", policy_path.display()))?;
    std::fs::create_dir_all(out_dir)?;

    let init_data = make_init_data(&policy)?;
    let template_hash = template_hash_of(&policy)?;
    let evidence = make_evidence(&init_data, 48)?;
    let digest = hex::encode(Sha256::digest(init_data.as_bytes()));

    std::fs::write(out_dir.join("initdata.toml"), &init_data)?;
    std::fs::write(
        out_dir.join("approved-templates.json"),
        serde_json::to_string_pretty(&json!([template_hash]))?,
    )?;
    std::fs::write(
        out_dir.join("stub-evidence-valid.json"),
        serde_json::to_string_pretty(&evidence)?,
    )?;

    println!("init-data sha256:      {digest}");
    println!("rules template sha256: {template_hash}");
    println!("fixtures written to    {}", out_dir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Component execution
// ---------------------------------------------------------------------------

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: wasmtime_wasi_http::WasiHttpCtx,
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

impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.http
    }
}

struct Runner {
    engine: wasmtime::Engine,
    linker: Linker<HostState>,
    component: Component,
}

impl Runner {
    fn new(component_path: &Path) -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config)?;
        let component = Component::from_file(&engine, component_path)
            .with_context(|| format!("load component {}", component_path.display()))?;
        let mut linker = Linker::<HostState>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker)?;
        Ok(Self {
            engine,
            linker,
            component,
        })
    }

    fn evaluate(&self, evidence: &[u8], init_data: &[u8], approved: &[u8]) -> Result<Value> {
        // Preopen a `cache/` dir so a real lower-layer verifier (TDX) can cache
        // DCAP collateral. The stub layer ignores it.
        let cache_dir = std::env::temp_dir().join("kata-policy-verifier-cache");
        std::fs::create_dir_all(&cache_dir).ok();
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        wasi.preopened_dir(
            &cache_dir,
            "cache",
            wasmtime_wasi::DirPerms::all(),
            wasmtime_wasi::FilePerms::all(),
        )?;
        let state = HostState {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
        };
        let mut store = Store::new(&self.engine, state);
        let bindings = Verifier::instantiate(&mut store, &self.component, &self.linker)?;
        let verifier_iface = bindings.trustee_verifier_verifier_interface();
        let verifier = verifier_iface.verifier();
        let resource = verifier.call_constructor(&mut store)?;

        let input = iface::VerifierInput {
            evidence: evidence.to_vec(),
            evidence_media_type: "application/json".to_string(),
            endorsements: vec![
                iface::Endorsement {
                    label: "init-data".to_string(),
                    media_type: "application/toml".to_string(),
                    payload: init_data.to_vec(),
                },
                iface::Endorsement {
                    label: "approved-templates".to_string(),
                    media_type: "application/json".to_string(),
                    payload: approved.to_vec(),
                },
            ],
        };
        let out = verifier.call_evaluate(
            &mut store,
            resource,
            &input,
            &iface::OptionalData::NotProvided,
            &iface::OptionalData::NotProvided,
        )?;
        serde_json::from_str(&out).context("component returned non-JSON string")
    }
}

// ---------------------------------------------------------------------------
// Scenario matrix
// ---------------------------------------------------------------------------

fn split_policy(policy: &str) -> Result<(String, String)> {
    let marker = "\npolicy_data := ";
    let at = policy
        .find(marker)
        .ok_or_else(|| anyhow!("fixture policy has no policy_data assignment"))?;
    Ok((
        policy[..at + 1].to_string(),
        policy[at + 1 + "policy_data := ".len()..].to_string(),
    ))
}

fn expect_reject(claims: &Value, needle: &str, label: &str) -> Result<()> {
    let err = claims
        .get("error")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("[{label}] expected rejection, got acceptance: {claims}"))?;
    if !err.contains(needle) {
        bail!("[{label}] rejected for the wrong reason (wanted `{needle}`): {err}");
    }
    Ok(())
}

fn expect_accept(claims: &Value, label: &str) -> Result<()> {
    if let Some(err) = claims.get("error") {
        bail!("[{label}] expected acceptance, got rejection: {err}");
    }
    for key in ["init_data_binding_valid", "structure_valid"] {
        if claims["kata_policy"][key] != json!(true) {
            bail!("[{label}] claim kata_policy.{key} is not true: {claims}");
        }
    }
    if claims.get("hardware").and_then(Value::as_object).is_none() {
        bail!("[{label}] hardware claims missing from output");
    }
    Ok(())
}

fn run_scenarios(component: &Path, test_data: &Path) -> Result<()> {
    let init_data = std::fs::read_to_string(test_data.join("initdata.toml"))
        .with_context(|| format!("read {}/initdata.toml — run gen-fixtures first", test_data.display()))?;
    let approved = std::fs::read(test_data.join("approved-templates.json"))?;

    // Recover the embedded policy through the same parser under test is
    // circular; instead re-read it from the TOML directly.
    let doc = kata_policy_core::InitData::parse(init_data.as_bytes())
        .map_err(|e| anyhow!("fixture initdata.toml invalid: {e}"))?;
    let policy = doc
        .data
        .get("policy.rego")
        .ok_or_else(|| anyhow!("fixture init-data lacks policy.rego"))?
        .clone();
    let (rules_region, policy_data_json) = split_policy(&policy)?;

    let runner = Runner::new(component)?;
    let mut failures = 0usize;

    let mut check = |label: &str, result: Result<()>| match result {
        Ok(()) => println!("PASS  {label}"),
        Err(e) => {
            failures += 1;
            println!("FAIL  {label}: {e:#}");
        }
    };

    let eval = |init_data: &str, register_len: usize, evidence_override: Option<Value>| -> Result<Value> {
        let evidence = match evidence_override {
            Some(v) => v,
            None => make_evidence(init_data, register_len)?,
        };
        runner.evaluate(
            serde_json::to_vec(&evidence)?.as_slice(),
            init_data.as_bytes(),
            &approved,
        )
    };

    // (a) valid template + valid data -> accept (TDX-style 48-byte register
    // and SNP-style 32-byte register).
    for (reg, name) in [(48, "tdx"), (32, "snp")] {
        let claims = eval(&init_data, reg, None)?;
        check(
            &format!("(a) valid policy accepted ({name} register)"),
            expect_accept(&claims, "a").and_then(|()| {
                if claims["kata_policy"]["approved_rule_template"] != json!(true) {
                    bail!("approved_rule_template != true: {}", claims["kata_policy"]);
                }
                if claims["kata_policy"]["images"].as_array().map_or(true, Vec::is_empty) {
                    bail!("expected non-empty images claim: {}", claims["kata_policy"]);
                }
                Ok(())
            }),
        );
    }

    // (b) same template, different image digest -> accept, new images claim.
    {
        let mut pd: Value = serde_json::from_str(&policy_data_json)?;
        let mut changed = false;
        if let Some(containers) = pd.get_mut("containers").and_then(Value::as_array_mut) {
            for c in containers.iter_mut() {
                if let Some(name) = c
                    .pointer_mut("/OCI/Annotations/io.kubernetes.cri.image-name")
                {
                    *name = json!("registry.example.com/tampered/other-app:2.0");
                    changed = true;
                    break;
                }
            }
        }
        let result = if !changed {
            Err(anyhow!("could not locate an image reference to modify"))
        } else {
            let policy_b = format!("{rules_region}policy_data := {}", serde_json::to_string_pretty(&pd)?);
            let init_b = make_init_data(&policy_b)?;
            let claims = eval(&init_b, 48, None)?;
            expect_accept(&claims, "b").and_then(|()| {
                let images = serde_json::to_string(&claims["kata_policy"]["images"])?;
                if claims["kata_policy"]["approved_rule_template"] != json!(true) {
                    bail!("template should still be approved");
                }
                if !images.contains("registry.example.com/tampered/other-app:2.0") {
                    bail!("images claim does not reflect the new reference: {images}");
                }
                Ok(())
            })
        };
        check("(b) new image digest accepted with updated images claim", result);
    }

    // (c) modified rule -> template hash mismatch (well-formed, unapproved).
    {
        let policy_c = format!(
            "{rules_region}default ExecProcessRequest := true\n\npolicy_data := {policy_data_json}"
        );
        let init_c = make_init_data(&policy_c)?;
        let claims = eval(&init_c, 48, None)?;
        check(
            "(c) modified rule -> approved_rule_template=false",
            expect_accept(&claims, "c").and_then(|()| {
                if claims["kata_policy"]["approved_rule_template"] != json!(false) {
                    bail!("tampered rules must not match the approved template");
                }
                Ok(())
            }),
        );
    }

    // (d) unauthorized exec command in policy_data -> facts reflect it.
    {
        let mut pd: Value = serde_json::from_str(&policy_data_json)?;
        pd["request_defaults"]["ExecProcessRequest"]["allowed_commands"] =
            json!(["/bin/sh -c anything"]);
        let policy_d = format!("{rules_region}policy_data := {}", serde_json::to_string_pretty(&pd)?);
        let init_d = make_init_data(&policy_d)?;
        let claims = eval(&init_d, 48, None)?;
        check(
            "(d) exec allowance surfaces in exec_commands claim",
            expect_accept(&claims, "d").and_then(|()| {
                let kp = &claims["kata_policy"];
                let cmds = serde_json::to_string(&kp["exec_commands"])?;
                if !cmds.contains("/bin/sh -c anything") {
                    bail!("exec_commands does not surface the allowance: {kp}");
                }
                if kp["flags"]["exec_allowed"] != json!(true) {
                    bail!("flags.exec_allowed should be true: {kp}");
                }
                Ok(())
            }),
        );
    }

    // (e) Rego rules smuggled inside/after policy_data -> structural reject.
    {
        let policy_e1 = format!("{policy}\ndefault CreateContainerRequest := true\n");
        let init_e1 = make_init_data(&policy_e1)?;
        check(
            "(e) rule appended after policy_data rejected",
            expect_reject(&eval(&init_e1, 48, None)?, "structural", "e1"),
        );

        let policy_e2 = format!(
            "{rules_region}policy_data := {} default CreateContainerRequest := true",
            policy_data_json.trim_end()
        );
        let init_e2 = make_init_data(&policy_e2)?;
        check(
            "(e) rule smuggled on the policy_data line rejected",
            expect_reject(&eval(&init_e2, 48, None)?, "structural", "e2"),
        );

        let policy_e3 = format!("{policy}policy_data := {{}}\n");
        let init_e3 = make_init_data(&policy_e3)?;
        check(
            "(e) second policy_data assignment rejected",
            expect_reject(&eval(&init_e3, 48, None)?, "structural", "e3"),
        );
    }

    // (f) init-data hash != MRCONFIGID -> binding reject.
    {
        let mut evidence = make_evidence(&init_data, 48)?;
        let good = evidence["claims"]["init_data"].as_str().unwrap().to_string();
        let flipped = format!("{}{}", if &good[..1] == "0" { "1" } else { "0" }, &good[1..]);
        evidence["claims"]["init_data"] = json!(flipped);
        check(
            "(f) init-data digest != measured MRCONFIGID rejected",
            expect_reject(&eval(&init_data, 48, Some(evidence))?, "binding", "f"),
        );
    }

    // Bonus: invalid quote fails closed before any policy claims are made.
    {
        let evidence = json!({"valid": false});
        check(
            "(g) invalid hardware quote rejected",
            expect_reject(
                &eval(&init_data, 48, Some(evidence))?,
                "hardware evidence verification failed",
                "g",
            ),
        );
    }

    if failures > 0 {
        bail!("{failures} scenario(s) failed");
    }
    println!("all scenarios passed");
    Ok(())
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::GenFixtures { policy, out_dir } => gen_fixtures(&policy, &out_dir),
        Command::Run {
            component,
            evidence_json,
            init_data,
            approved_templates,
        } => {
            let runner = Runner::new(&component)?;
            let claims = runner.evaluate(
                &std::fs::read(&evidence_json)?,
                &std::fs::read(&init_data)?,
                &std::fs::read(&approved_templates)?,
            )?;
            if let Some(err) = claims.get("error") {
                eprintln!("{claims}");
                return Err(anyhow!("attestation failed: {err}"));
            }
            println!("{}", serde_json::to_string_pretty(&claims)?);
            Ok(())
        }
        Command::Scenarios {
            component,
            test_data,
        } => run_scenarios(&component, &test_data),
    }
}

// ---------------------------------------------------------------------------
// Real TDX evidence tests
//
// Fixtures live in `../test_data/server/`, captured from a live TDX guest that
// was launched with `final-initdata.toml` as its init-data:
//   - quote.bin            raw TDX attestation quote (also base64 in evidence.json)
//   - evidence.json        { quote, cc_eventlog } as consumed by the TDX verifier
//   - final-initdata.toml  the CoCo init-data measured into MRCONFIGID
//   - nonce.bin / nonce.txt the freshness challenge bound into REPORT_DATA
// ---------------------------------------------------------------------------
#[cfg(test)]
mod real_tdx {
    use super::*;
    use std::path::PathBuf;

    // sha256(final-initdata.toml) — the value measured into MRCONFIGID.
    const EXPECTED_INITDATA_DIGEST: &str =
        "10074640873396a07fa6e4c711d5a330cf51c8698cb4556af68749696d36ed58";
    // sha256(rules.rego + "\n") — the approved static-rules template.
    const EXPECTED_TEMPLATE_HASH: &str =
        "67880bf93b0f55c86bda68263b1741bcc37a6bed2e76ae414af45cc3d1271018";

    // TDX Quote v4: 48-byte header + 584-byte TD report body.
    // Within the body: MRCONFIGID at [184..232], REPORT_DATA at [520..584].
    const HEADER_LEN: usize = 48;
    const BODY_LEN: usize = 584;

    fn server(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../test_data/server")
            .join(name)
    }

    /// Hermetic: the committed real quote cryptographically binds the committed
    /// init-data (MRCONFIGID) and the challenge nonce (REPORT_DATA), and its
    /// embedded policy is the approved rules template. No network / no wasm.
    #[test]
    fn real_quote_binds_initdata_and_nonce() {
        let quote = std::fs::read(server("quote.bin")).expect("read quote.bin");
        assert!(
            quote.len() >= HEADER_LEN + BODY_LEN,
            "quote too short: {}",
            quote.len()
        );
        assert_eq!(
            u16::from_le_bytes([quote[0], quote[1]]),
            4,
            "expected TDX quote version 4"
        );
        let body = &quote[HEADER_LEN..HEADER_LEN + BODY_LEN];
        let mrconfigid = &body[184..232];
        let report_data = &body[520..584];

        // init-data binding: MRCONFIGID == sha256(init-data), left-aligned in 48 bytes.
        let initdata = std::fs::read(server("final-initdata.toml")).expect("read init-data");
        let digest = Sha256::digest(&initdata);
        assert_eq!(
            hex::encode(digest),
            EXPECTED_INITDATA_DIGEST,
            "init-data digest drifted from the captured quote"
        );
        let mut expected_reg = digest.to_vec();
        expected_reg.resize(48, 0);
        assert_eq!(
            mrconfigid,
            expected_reg.as_slice(),
            "MRCONFIGID mismatch: quote={} expected={}",
            hex::encode(mrconfigid),
            hex::encode(&expected_reg)
        );

        // nonce binding: REPORT_DATA carries the base64url nonce string (nonce.txt).
        let nonce_txt = std::fs::read(server("nonce.txt")).expect("read nonce.txt");
        let nonce = nonce_txt.split(|b| *b == b'\n').next().unwrap();
        assert!(!nonce.is_empty(), "nonce.txt empty");
        assert!(
            report_data.starts_with(nonce),
            "REPORT_DATA does not carry the nonce: report_data={} nonce={}",
            hex::encode(report_data),
            String::from_utf8_lossy(nonce)
        );

        // the embedded policy is the approved static-rules template.
        let doc = kata_policy_core::InitData::parse(&initdata).expect("parse init-data TOML");
        let policy = doc.data.get("policy.rego").expect("init-data has policy.rego");
        let structure = kata_policy_core::parse_policy_structure(policy).expect("policy parses");
        assert_eq!(
            structure.template_hash, EXPECTED_TEMPLATE_HASH,
            "embedded rules template drifted"
        );
    }

    /// End-to-end through the composed kata-policy + real-TDX component against
    /// the captured evidence.
    ///
    /// Ignored by default — it needs the composed component built
    /// (`LOWER=tdx bash kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh`)
    /// and outbound network to Intel PCS for DCAP collateral. Run explicitly:
    /// `cargo test -p kata-policy-verifier-test -- --ignored real_tdx`.
    #[test]
    #[ignore = "requires kata_policy_tdx_verifier_component.wasm + Intel PCS network"]
    fn component_accepts_real_evidence() {
        let component = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-wasip2/release/kata_policy_tdx_verifier_component.wasm");
        assert!(
            component.exists(),
            "composed component missing: {} — build it with LOWER=tdx",
            component.display()
        );

        let evidence = std::fs::read(server("evidence.json")).expect("read evidence.json");
        let initdata = std::fs::read(server("final-initdata.toml")).expect("read init-data");
        let approved = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/approved-templates.json"),
        )
        .expect("read approved-templates.json");

        let runner = Runner::new(&component).expect("load composed component");
        let claims = runner
            .evaluate(&evidence, &initdata, &approved)
            .expect("evaluate real evidence");

        assert!(claims.get("error").is_none(), "verification failed: {claims}");

        // Policy layer.
        let kp = &claims["kata_policy"];
        assert_eq!(kp["init_data_binding_valid"], json!(true));
        assert_eq!(kp["structure_valid"], json!(true));
        assert_eq!(kp["approved_rule_template"], json!(true));
        assert_eq!(kp["template_hash"], json!(EXPECTED_TEMPLATE_HASH));
        assert_eq!(kp["init_data_digest"], json!(EXPECTED_INITDATA_DIGEST));
        // policy_data facts as configured for this deployment.
        assert_eq!(kp["flags"]["read_stream_allowed"], json!(true));
        assert_eq!(kp["flags"]["write_stream_allowed"], json!(false));
        assert_eq!(kp["flags"]["close_stdin_allowed"], json!(false));
        assert_eq!(kp["flags"]["exec_allowed"], json!(true));
        assert!(
            kp["images"].as_array().map_or(false, |a| !a.is_empty()),
            "expected a non-empty images claim"
        );

        // Hardware layer (real TDX quote verified via dcap-qvl).
        let hw = &claims["hardware"];
        assert_eq!(
            hw["init_data"].as_str().unwrap_or_default(),
            format!("{EXPECTED_INITDATA_DIGEST}{}", "0".repeat(32)),
            "hardware MRCONFIGID claim mismatch"
        );
        let nonce_txt = std::fs::read_to_string(server("nonce.txt")).unwrap();
        let nonce_hex = hex::encode(nonce_txt.trim().as_bytes());
        assert!(
            hw["report_data"]
                .as_str()
                .unwrap_or_default()
                .starts_with(&nonce_hex),
            "hardware REPORT_DATA claim does not carry the nonce"
        );
        // dcap-qvl produced a TCB status string (e.g. UpToDate / OutOfDate).
        assert!(
            hw["tcb_status"].as_str().map_or(false, |s| !s.is_empty()),
            "expected a tcb_status from dcap-qvl"
        );
    }
}
