//! Core logic for the Kata agent-policy verification component.
//!
//! Everything in this crate is pure computation over attacker-controlled
//! bytes: no I/O, no panics on malformed input, all failures reported as
//! `Err(String)`. The WIT component in `kata-policy-verifier-component` is a
//! thin wrapper around [`evaluate_kata_policy`].

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;

/// The one assignment genpolicy appends to its static rules. The match is
/// byte-exact and anchored to the start of a line; no Rego parsing or
/// canonicalization happens anywhere in this crate.
const POLICY_DATA_ASSIGN: &str = "policy_data := ";

/// Init-data document as defined by the CoCo initdata spec
/// (<https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md>):
/// a TOML file with `version`, `algorithm` and a `[data]` table of
/// filename -> plaintext content.
#[derive(Deserialize)]
pub struct InitData {
    pub version: String,
    pub algorithm: String,
    pub data: BTreeMap<String, String>,
}

impl InitData {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(raw).map_err(|e| format!("init-data is not UTF-8: {e}"))?;
        let doc: InitData =
            toml::from_str(text).map_err(|e| format!("init-data is not valid TOML: {e}"))?;
        Ok(doc)
    }

    /// Digest of the raw init-data bytes using the algorithm the document
    /// itself declares. This is the value the guest puts into
    /// MRCONFIGID / HOSTDATA at TEE launch.
    pub fn digest(&self, raw: &[u8]) -> Result<Vec<u8>, String> {
        match self.algorithm.to_ascii_lowercase().as_str() {
            "sha256" => Ok(Sha256::digest(raw).to_vec()),
            "sha384" => Ok(Sha384::digest(raw).to_vec()),
            "sha512" => Ok(Sha512::digest(raw).to_vec()),
            other => Err(format!("unsupported init-data digest algorithm `{other}`")),
        }
    }
}

/// Check that the init-data digest is what the hardware measured.
///
/// TEE registers are fixed-width (MRCONFIGID: 48 bytes, HOSTDATA: 32 bytes)
/// while digests may be shorter; the CoCo convention is to left-align the
/// digest and zero-pad the rest, so that is the only padding accepted here.
pub fn binding_matches(digest: &[u8], measured: &[u8]) -> bool {
    if digest.len() > measured.len() {
        return false;
    }
    let (head, tail) = measured.split_at(digest.len());
    head == digest && tail.iter().all(|b| *b == 0)
}

/// Result of the strict structural parse of `policy.rego`.
#[derive(Debug)]
pub struct PolicyStructure {
    /// sha256 over the static rules region, hex-encoded.
    pub template_hash: String,
    /// The parsed `policy_data` JSON object.
    pub policy_data: Map<String, Value>,
}

/// Strict structural parse of a genpolicy-generated `policy.rego`.
///
/// The file must be exactly:
///
/// ```text
/// <static rules region (byte-exact template)>
/// policy_data := <one pure-JSON object>
/// <ASCII whitespace only>
/// ```
///
/// The rules region is not interpreted at all — it is hashed byte-exactly and
/// later compared against approved template hashes, so any smuggled rule,
/// import or definition inside it changes the hash. The JSON value is parsed
/// with serde_json (pure JSON, no Rego), and anything after it other than
/// whitespace is rejected, so nothing can be smuggled inside or after
/// `policy_data` either.
pub fn parse_policy_structure(policy: &str) -> Result<PolicyStructure, String> {
    // Find every line that starts with the assignment marker. Line starts are
    // offset 0 and every byte following a '\n'; anything else (including an
    // occurrence inside a single-line JSON string) is not an assignment.
    let mut assign_offsets = Vec::new();
    let mut line_start = true;
    for (i, b) in policy.bytes().enumerate() {
        if line_start && policy[i..].starts_with(POLICY_DATA_ASSIGN) {
            assign_offsets.push(i);
        }
        line_start = b == b'\n';
    }

    let assign_at = match assign_offsets.as_slice() {
        [one] => *one,
        [] => return Err("structural violation: no `policy_data := ` assignment found".into()),
        many => {
            return Err(format!(
                "structural violation: expected exactly one `policy_data := ` assignment, found {}",
                many.len()
            ))
        }
    };

    let rules_region = &policy[..assign_at];
    let json_text = &policy[assign_at + POLICY_DATA_ASSIGN.len()..];

    // Parse exactly one JSON value and note how many bytes it consumed.
    let mut stream = serde_json::Deserializer::from_str(json_text).into_iter::<Value>();
    let value = match stream.next() {
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(format!("policy_data is not pure JSON: {e}")),
        None => return Err("structural violation: `policy_data := ` has no value".into()),
    };
    let consumed = stream.byte_offset();

    // Nothing but whitespace may follow the JSON value: this rejects rules
    // appended after the assignment.
    let trailer = &json_text[consumed..];
    if !trailer.bytes().all(|b| b.is_ascii_whitespace()) {
        return Err(
            "structural violation: unexpected content after the policy_data JSON value".into(),
        );
    }

    let policy_data = match value {
        Value::Object(map) => map,
        other => {
            return Err(format!(
                "structural violation: policy_data must be a JSON object, got {}",
                json_type_name(&other)
            ))
        }
    };

    Ok(PolicyStructure {
        template_hash: hex::encode(Sha256::digest(rules_region.as_bytes())),
        policy_data,
    })
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Facts extracted from `policy_data` for the appraisal policy engine.
pub struct PolicyFacts {
    pub images: Vec<Value>,
    pub exec_commands: Vec<String>,
    pub exec_command_regex: Vec<String>,
    pub flags: Value,
}

/// Pull the security-relevant facts out of the (already pure-JSON-parsed)
/// `policy_data`. Extraction is best-effort over known genpolicy field names;
/// absent fields simply yield empty lists / null flags rather than errors, so
/// the appraisal policy can decide how to treat missing information.
pub fn extract_facts(policy_data: &Map<String, Value>) -> PolicyFacts {
    let mut images = Vec::new();
    let mut exec_commands = Vec::new();
    let mut exec_command_regex = Vec::new();
    let mut any_terminal = false;
    let mut sandbox_pidns = false;

    if let Some(containers) = policy_data.get("containers").and_then(Value::as_array) {
        for container in containers {
            // Image reference: genpolicy stores it in the CRI annotation.
            let reference = container
                .pointer("/OCI/Annotations/io.kubernetes.cri.image-name")
                .and_then(Value::as_str);

            // Image integrity: every layer genpolicy resolved for this
            // container, identified by its (digest, dm-verity root hash).
            let mut digests = Vec::new();
            if let Some(storages) = container.get("storages").and_then(Value::as_array) {
                for storage in storages {
                    if let Some(chain) = storage
                        .pointer("/source")
                        .and_then(Value::as_str)
                        .filter(|s| s.contains(':'))
                    {
                        digests.push(json!(chain));
                    }
                }
            }

            if reference.is_some() || !digests.is_empty() {
                // A digest-pinned reference ("repo@sha256:...") is the image
                // integrity anchor in guest-pull deployments; surface it as
                // its own claim so the appraisal policy can require it.
                let digest = reference.and_then(|r| r.split_once('@')).map(|(_, d)| d);
                images.push(json!({
                    "reference": reference,
                    "digest": digest,
                    "layer_digests": digests,
                }));
            }

            if container
                .pointer("/OCI/Process/Terminal")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                any_terminal = true;
            }
            if container
                .get("sandbox_pidns")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                sandbox_pidns = true;
            }

            // Per-container exec allowances.
            if let Some(cmds) = container.get("exec_commands").and_then(Value::as_array) {
                for cmd in cmds {
                    if let Some(s) = cmd.as_str() {
                        exec_commands.push(s.to_string());
                    }
                }
            }
        }
    }

    let request_defaults = policy_data.get("request_defaults");
    if let Some(exec) = request_defaults.and_then(|rd| rd.get("ExecProcessRequest")) {
        // Field name changed across genpolicy releases: accept both.
        for key in ["allowed_commands", "commands"] {
            if let Some(cmds) = exec.get(key).and_then(Value::as_array) {
                for cmd in cmds {
                    if let Some(s) = cmd.as_str() {
                        exec_commands.push(s.to_string());
                    }
                }
            }
        }
        if let Some(regexes) = exec.get("regex").and_then(Value::as_array) {
            for re in regexes {
                if let Some(s) = re.as_str() {
                    exec_command_regex.push(s.to_string());
                }
            }
        }
    }

    let default_bool = |key: &str| {
        request_defaults
            .and_then(|rd| rd.get(key))
            .and_then(Value::as_bool)
    };

    let flags = json!({
        "container_count": policy_data
            .get("containers")
            .and_then(Value::as_array)
            .map(Vec::len),
        "exec_allowed": !exec_commands.is_empty() || !exec_command_regex.is_empty(),
        "any_container_terminal": any_terminal,
        "sandbox_pidns": sandbox_pidns,
        "read_stream_allowed": default_bool("ReadStreamRequest"),
        "write_stream_allowed": default_bool("WriteStreamRequest"),
        "close_stdin_allowed": default_bool("CloseStdinRequest"),
    });

    PolicyFacts {
        images,
        exec_commands,
        exec_command_regex,
        flags,
    }
}

/// Full evaluation: init-data binding, structural parse, template check and
/// fact extraction. Returns the `kata_policy` claims object.
///
/// Hard failures (`Err`) are conditions under which no claim about the policy
/// can be trusted at all: the init-data is not the one the hardware measured,
/// or `policy.rego` does not have the required structure so nothing can be
/// safely extracted from it. An unapproved-but-well-formed template is *not* a
/// hard failure: it is reported as `approved_rule_template: false` together
/// with the extracted facts, so the appraisal policy engine makes the call.
pub fn evaluate_kata_policy(
    init_data_raw: &[u8],
    approved_template_hashes: &[String],
    measured_init_data: &[u8],
) -> Result<Value, String> {
    let init_data = InitData::parse(init_data_raw)?;
    let digest = init_data.digest(init_data_raw)?;

    if !binding_matches(&digest, measured_init_data) {
        return Err(format!(
            "init-data binding failure: {}({} bytes of init-data) = {} does not match the \
             hardware-measured value {}",
            init_data.algorithm.to_ascii_lowercase(),
            init_data_raw.len(),
            hex::encode(&digest),
            hex::encode(measured_init_data),
        ));
    }

    let policy = init_data
        .data
        .get("policy.rego")
        .ok_or("init-data has no `policy.rego` entry in its [data] section")?;

    let structure = parse_policy_structure(policy)?;

    let approved = approved_template_hashes
        .iter()
        .any(|h| h.trim().eq_ignore_ascii_case(&structure.template_hash));

    let facts = extract_facts(&structure.policy_data);

    Ok(json!({
        "init_data_binding_valid": true,
        "init_data_digest": hex::encode(&digest),
        "init_data_algorithm": init_data.algorithm.to_ascii_lowercase(),
        "structure_valid": true,
        "template_hash": structure.template_hash,
        "approved_rule_template": approved,
        "images": facts.images,
        "exec_commands": facts.exec_commands,
        "exec_command_regex": facts.exec_command_regex,
        "flags": facts.flags,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = "package agent_policy\n\ndefault CreateContainerRequest := false\n\n";

    fn policy_with(data: &str) -> String {
        format!("{RULES}policy_data := {data}\n")
    }

    fn rules_hash() -> String {
        hex::encode(Sha256::digest(RULES.as_bytes()))
    }

    #[test]
    fn accepts_well_formed_policy() {
        let s = parse_policy_structure(&policy_with(r#"{"containers":[]}"#)).unwrap();
        assert_eq!(s.template_hash, rules_hash());
        assert!(s.policy_data.contains_key("containers"));
    }

    #[test]
    fn accepts_multi_line_json() {
        let s = parse_policy_structure(&policy_with("{\n  \"containers\": []\n}")).unwrap();
        assert_eq!(s.template_hash, rules_hash());
    }

    #[test]
    fn rejects_missing_assignment() {
        assert!(parse_policy_structure(RULES).is_err());
    }

    #[test]
    fn rejects_duplicate_assignment() {
        let p = format!("{}policy_data := {{}}\n", policy_with("{}"));
        let err = parse_policy_structure(&p).unwrap_err();
        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn rejects_rule_after_policy_data() {
        let p = format!(
            "{}\nAllowRequestsFailingPolicy := true\n",
            policy_with(r#"{"containers":[]}"#).trim_end()
        );
        let err = parse_policy_structure(&p).unwrap_err();
        assert!(err.contains("after the policy_data"), "{err}");
    }

    #[test]
    fn rejects_rego_smuggled_as_json_suffix() {
        // Attacker appends a rego rule directly after the JSON object.
        let p = policy_with(r#"{"containers":[]} default ExecProcessRequest := true"#);
        assert!(parse_policy_structure(&p).is_err());
    }

    #[test]
    fn rego_inside_json_string_is_inert_data() {
        // Rego text inside a JSON string is data, not rules: structure stays
        // valid, and the template hash still pins the actual rules region.
        let p = policy_with(r#"{"x":"default ExecProcessRequest := true"}"#);
        let s = parse_policy_structure(&p).unwrap();
        assert_eq!(s.template_hash, rules_hash());
    }

    #[test]
    fn multiline_json_with_fake_assignment_line_is_rejected() {
        // A second line-start `policy_data := ` (even inside what would be a
        // valid JSON layout) makes the assignment ambiguous -> reject.
        let p = format!("{RULES}policy_data := {{\"k\":\npolicy_data := 1}}\n");
        let err = parse_policy_structure(&p).unwrap_err();
        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn rejects_non_object_policy_data() {
        assert!(parse_policy_structure(&policy_with("[1,2]")).is_err());
        assert!(parse_policy_structure(&policy_with("42")).is_err());
    }

    #[test]
    fn rejects_missing_value() {
        let p = format!("{RULES}policy_data := \n");
        assert!(parse_policy_structure(&p).is_err());
    }

    #[test]
    fn modified_rules_change_template_hash() {
        let p = format!(
            "{}default ExecProcessRequest := true\npolicy_data := {{}}\n",
            RULES
        );
        let s = parse_policy_structure(&p).unwrap();
        assert_ne!(s.template_hash, rules_hash());
    }

    #[test]
    fn binding_padding_rules() {
        let digest = [0xaau8; 32];
        let mut mrconfigid = [0u8; 48];
        mrconfigid[..32].copy_from_slice(&digest);
        assert!(binding_matches(&digest, &mrconfigid)); // zero-padded TDX
        assert!(binding_matches(&digest, &digest)); // exact SNP
        mrconfigid[47] = 1;
        assert!(!binding_matches(&digest, &mrconfigid)); // non-zero pad
        assert!(!binding_matches(&[0xaa; 48], &digest)); // digest longer
    }

    #[test]
    fn initdata_binding_end_to_end() {
        let toml = "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"policy.rego\" = '''\n"
            .to_string()
            + RULES
            + "policy_data := {\"containers\":[]}\n'''\n";
        let digest = Sha256::digest(toml.as_bytes());
        let approved = vec![rules_hash()];

        let claims = evaluate_kata_policy(toml.as_bytes(), &approved, &digest).unwrap();
        assert_eq!(claims["init_data_binding_valid"], json!(true));
        assert_eq!(claims["approved_rule_template"], json!(true));

        let mut wrong = digest.to_vec();
        wrong[0] ^= 1;
        let err = evaluate_kata_policy(toml.as_bytes(), &approved, &wrong).unwrap_err();
        assert!(err.contains("binding failure"), "{err}");
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        assert!(InitData::parse(&[0xff, 0xfe]).is_err());
        assert!(InitData::parse(b"not toml at [[").is_err());
        assert!(evaluate_kata_policy(b"version = \"1\"", &[], &[0; 32]).is_err());
    }
}
