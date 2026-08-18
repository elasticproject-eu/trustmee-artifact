# Kata Policy Verifier Component

A TrustMee wasm verification component that verifies the Kata Containers agent policy embedded in a confidential VM's init-data.

- It **imports** `trustee:verifier/verifier-interface` and calls the composed
  lower-layer hardware component (TDX or SNP) for quote/report verification.
- It **exports** the same interface, so it can be used directly by
  `wasm-verifier-lib` or stacked under further layers.

## What it verifies

1. **Hardware evidence** — forwarded verbatim to the composed lower layer.
   If the quote/report is invalid, verification fails.
2. **Init-data binding** — `digest(init-data TOML)` (algorithm taken from the
   document itself, `sha256` in the samples) must equal the hardware-measured
   value: MRCONFIGID on TDX, HOSTDATA on SNP. Both hardware verifiers in this
   repo expose it as the top-level hex `init_data` claim; shorter digests must
   be zero-padded to the register width, anything else is a binding failure.
3. **Strict structural parse of `policy.rego`** (attacker-controlled input;
   no Rego canonicalization or normalization anywhere):
   - exactly one line starting with `policy_data := `;
   - everything before it is the *static rules region*, hashed **byte-exactly**
     with sha256 and matched against the approved template hashes;
   - everything after `policy_data := ` must be exactly one pure-JSON object
     (serde_json, multi-line/pretty JSON supported) followed by nothing but
     ASCII whitespace.

   Any extra rule, import or definition — before the assignment (changes the
   template hash), on the assignment line, inside `policy_data` (breaks JSON),
   or after it (non-whitespace trailer) — is rejected.
4. **Fact extraction from `policy_data`** — image references (with digests,
   for digest-pinned references and dm-verity layer storages), exec
   allowances (`request_defaults.ExecProcessRequest.allowed_commands`/`regex`
   and per-container `exec_commands`), and debug/interactive flags
   (terminal, stream read/write, stdin, sandbox pidns).

Facts are emitted as claims, not only booleans, so the Trustee policy engine
appraises them:

```json
{
  "kata_policy": {
    "init_data_binding_valid": true,
    "structure_valid": true,
    "template_hash": "2a6e0608…",
    "approved_rule_template": true,
    "images": [ { "reference": "…", "digest": "sha256:…", "layer_digests": [] } ],
    "exec_commands": [],
    "exec_command_regex": [],
    "flags": { "exec_allowed": false, "any_container_terminal": false, "…": "…" }
  },
  "hardware": { "…": "nested hardware component claims" }
}
```

Failure semantics: invalid quote, binding mismatch and structural violations
are hard failures (`{"status":"failed","error":"…"}`) — no policy claim can
be trusted in those states. A well-formed but *unapproved* rules template is
not a hard failure: it is reported as `approved_rule_template: false`
together with the extracted facts.

## Endorsements (inputs)

| label | content |
|---|---|
| `init-data` | full plaintext init-data TOML (CoCo initdata spec: `algorithm`, `version`, `[data]` with `aa.toml` / `cdh.toml` / `policy.rego`) |
| `approved-templates` | JSON list of sha256 hex hashes of approved static rule templates |

Approved template hashes are versioned upstream artifacts, not something
operators invent: the hash is literally `sha256(rules.rego + "\n")` for the
`rules.rego` shipped with the genpolicy release in use (genpolicy emits
`format!("{rules}\npolicy_data := {pretty_json}")`).

## Layout

- `kata-policy-core/` — all verification logic; pure computation, `Err(String)`
  on any malformed input, natively unit-tested (`cargo test -p kata-policy-core`).
- `kata-policy-verifier-component/` — WIT glue (imports + exports
  `trustee:verifier/verifier-interface`).
- `stub-hardware-verifier-component/` — test stand-in for the TDX/SNP layer;
  its "quote" is JSON: `{"valid": bool, "claims": {"init_data": "<hex>", …}}`.
- `kata-policy-verifier-test/` — host harness: fixture generation, single runs,
  and the scenario matrix.
- `test_data/` — a real genpolicy-produced policy and derived fixtures (see below).

## Build and compose

```bash
# one-time: cargo install wac-cli
bash kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh          # stub lower layer (tests)
LOWER=tdx bash kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh # real TDX lower layer
LOWER=snp bash kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh # real SNP lower layer
```

## Tests (no live TEE needed)

```bash
cargo test -p kata-policy-core          # structural-parser unit tests
cargo run -p kata-policy-verifier-test --release -- scenarios \
  --component target/wasm32-wasip2/release/kata_policy_stub_verifier_component.wasm \
  --test-data kata-policy-verifier/test_data
```

The scenario matrix covers: (a) valid template + valid data accepted (TDX 48-byte
and SNP 32-byte registers); (b) same template with a different image digest
accepted with the new `images` claim; (c) modified rule → template hash
mismatch; (d) unauthorized exec command surfaced in the facts; (e) Rego rules
smuggled on/inside/after `policy_data` → structural reject; (f) init-data
hash ≠ MRCONFIGID → binding reject; plus an invalid-quote reject.

Single manual run:

```bash
cargo run -p kata-policy-verifier-test --release -- run \
  --component target/wasm32-wasip2/release/kata_policy_stub_verifier_component.wasm \
  --evidence-json kata-policy-verifier/test_data/stub-evidence-valid.json \
  --init-data kata-policy-verifier/test_data/initdata.toml \
  --approved-templates kata-policy-verifier/test_data/approved-templates.json
```

## Regenerating the fixtures

`test_data/policy.rego` is real genpolicy output. The `genpolicy` binary,
`rules.rego` and `genpolicy-settings.json` all come from the **Kata Containers
3.28.0** release (tag `3.28.0` → commit
`660e3bb6535b141c84430acb25b159857278d596`), taken from the
`kata-tools-static-3.28.0-amd64.tar.zst` release asset so nothing is mixed
across Kata versions:

```
$ genpolicy --version
Kata Containers policy tool (Rust): id: genpolicy, version: 0.1.0, commit: 660e3bb6535b141c84430acb25b159857278d596
```

The input Pod (`test_data/pod-one-container.yaml`) is the exact Pod that runs
on the cluster: `runtimeClassName: kata-qemu-tdx`, the
`agent.guest_components_rest_api=all` kernel-params annotation, the
digest-pinned image, command, env, `privileged` securityContext and the
`supplementalGroups` genpolicy requires for guest-pull. The
`io.katacontainers.config.hypervisor.cc_init_data` annotation is removed before
running genpolicy.

**One setting is overridden to match the target cluster:** `oci_version` in
`genpolicy-settings.json` is set to `1.2.1` (the stock 3.28.0 value is
`1.1.0`). This is the OCI runtime-spec version the target's genpolicy emits;
it lands verbatim as `"Version"` inside both OCI entries of `policy_data`, so
it must match or the init-data hash will not equal the measured MRCONFIGID.

```bash
sed -i 's/"oci_version": "1.1.0"/"oci_version": "1.2.1"/' genpolicy-settings.json
genpolicy -y pod-one-container.yaml -j genpolicy-settings.json -p rules.rego -r > policy.rego
```

Sanity checks the generated policy must pass (else the toolchain/settings do
not match the target):

```bash
test "$(grep -c '"Version": "1.2.1"' policy.rego)" -eq 2   # pause + workload
! grep -q '"Version": "1.1.0"' policy.rego
grep -A2 '"mount_point": "/run/kata-containers/sandbox/shm"' policy.rego   # fs_group null, shared false
! grep -q 'input.file_type' policy.rego                    # current CopyFileRequest format
grep -q '"io.katacontainers.config.hypervisor.kernel_params": "agent.guest_components_rest_api=all"' policy.rego
```

Then wrap it into the init-data document and derive the endorsements/evidence:

```bash
cargo run -p kata-policy-verifier-test --release -- gen-fixtures \
  --policy kata-policy-verifier/test_data/policy.rego \
  --out-dir kata-policy-verifier/test_data
```

This writes `initdata.toml` (CoCo initdata TOML carrying `policy.rego`
alongside `aa.toml`/`cdh.toml`), `approved-templates.json`
(`[sha256(rules region)]`) and `stub-evidence-valid.json` (stub hardware
claims whose `init_data` is the zero-padded sha256 of `initdata.toml`, i.e.
the MRCONFIGID a real TD launched with this init-data would carry).

For the fixtures currently checked in:

| artifact | value |
|---|---|
| approved rules template hash — `sha256(rules.rego + "\n")` | `67880bf93b0f55c86bda68263b1741bcc37a6bed2e76ae414af45cc3d1271018` |
| **TDX init-data binding — `sha256(initdata.toml)`** (expected MRCONFIGID) | `ff9ba74a1e71726663fd2f220d7338e0e6c97c0ce5f2100ffa9e11da950877c1` |

`initdata-realtdx.toml` and `initdata-realtdx-exec-unapproved.toml` embed the
**same** `policy.rego` (same approved template `67880bf9…`) but wrap it with
real-deployment `aa.toml`/`cdh.toml` carrying `YOUR_AS_HOST`/`YOUR_KBS_HOST`
placeholders; the `-exec-unapproved` variant additionally injects an unapproved
`request_defaults.ExecProcessRequest` allowance (surfaced by the verifier as
`exec_allowed: true` with the `exec_commands`/`exec_command_regex` facts). Their
bindings below are for the checked-in **placeholder** bytes — substituting real
KBS/AS hosts changes the TOML and therefore the MRCONFIGID:

| artifact | `sha256(TOML)` |
|---|---|
| `initdata-realtdx.toml` | `7cd15a2593923129a956d702817b9264a2ced74246051d1044feb4769ae7e32e` |
| `initdata-realtdx-exec-unapproved.toml` | `4f0aa82eb85d216aa6509a4df5a5745e8013735a195178362c1749dff503b5a1` |
