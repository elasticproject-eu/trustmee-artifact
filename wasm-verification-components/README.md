# WebAssembly Verification Components

This project contains standalone WebAssembly verification components used by TrustMee project.

Hardware (TEE) verifiers — each takes a quote/report and exports `trustee:verifier/verifier-interface`:

- `tdx-verifier/`: TDX-related items (`dcap-qvl-wasi`, `eventlog`, `tdx-verifier-component`, `tdx-verifier-test`)
- `snp-verifier/`: SNP-related items (`snp-verifier-component`, `snp-verifier-test`). Verifies the cert chain in-guest, so building it needs the containerized OpenSSL-for-wasm toolchain
- `snp-verifier-host-crypto/`: same SNP verification split differently (`snp-verifier-host-crypto-component`, `snp-verifier-host-crypto-test`). The component **imports** `trustee:verifier/snp-host-crypto-interface` and delegates cert-chain crypto to the host, so it builds with plain `cargo build` — no container, no OpenSSL cross-compile. The host must supply that import
- `sgx-verifier/`: SGX-related items (`sgx-verifier-component`, `sgx-verifier-test`); shares `dcap-qvl-wasi` with TDX and binds REPORT_DATA / CONFIGID. A real DCAP v3 quote from a non-debug enclave is committed as `sgx-verifier/test_data/sgx_dcap_v3_quote_not_debug.bin`

Layered components — these **import** a lower-layer verifier interface and export the same one, so they compose with `wac`:

- `bootloader-verifier/`: bootloader layer component (`bootloader-verifier-component`) that imports TDX verifier interface and verifies RTMR0/RTMR1 policy
- `kata-policy-verifier/`: verifies the Kata Containers agent policy embedded in a confidential VM's init-data (`kata-policy-core`, `kata-policy-verifier-component`, `kata-policy-verifier-test`, `stub-hardware-verifier-component`). Forwards hardware evidence to a composed TDX/SNP layer, binds `digest(init-data)` to MRCONFIGID/HOSTDATA, then strictly parses `policy.rego` and emits the extracted facts as claims. `stub-hardware-verifier-component` stands in for the hardware layer so the whole matrix runs without a live TEE; see [kata-policy-verifier/README.md](kata-policy-verifier/README.md)

Non-TEE verifiers:

- `recfa-verifier/`: ReCFA control-flow attestation items (`recfa-verifier-component`, `recfa-verifier-test`). Wraps the verifier from [ReCFA (ACSAC'21)](https://arxiv.org/abs/2110.11603) and replays a folded control-flow event stream against a CFI policy. Not a TEE verifier — it reports `hardware_rooted: false` and its evidence is unauthenticated, so read [recfa-verifier/README.md](recfa-verifier/README.md) before trusting a verdict

Test fixtures and tooling:

- `infinite-loop-verifier/`: deliberately malicious component (`infinite-loop-verifier-component`) whose `evaluate` is `loop {}`. Not a verifier — it exists so hosts can prove they contain a non-cooperative guest (wasmtime fuel or epoch interruption); a host that hangs on it will hang on any untrusted component
- `tools/component-signer/`: adds TrustMee signature expiry metadata and signs verifier components with `wasmsign2`

To write a new component, see [WRITING_A_VERIFIER_COMPONENT.md](WRITING_A_VERIFIER_COMPONENT.md).

## Build the component

From the repo root (no `cargo component` required; uses the native `wasm32-wasip2` target):

`cargo build --manifest-path Cargo.toml -p tdx-verifier-component --release --target wasm32-wasip2`

The resulting component is created at `target/wasm32-wasip2/release/tdx_verifier_component.wasm`.

For AMD SEV-SNP, use the builder script (it builds a containerized toolchain and OpenSSL for `wasm32-wasip2`):

`bash snp-verifier/snp-verifier-component/scripts/build-snp-wasm-component.sh`

The resulting component is created at `target/wasm32-wasip2/release/snp_verifier_component.wasm`.

The host-crypto SNP variant needs none of that, because the crypto lives on the host:

`bash snp-verifier-host-crypto/snp-verifier-host-crypto-component/scripts/build-snp-host-crypto-wasm-component.sh`

The resulting component is created at `target/wasm32-wasip2/release/snp_verifier_host_crypto_component.wasm`.

For Intel SGX (plain build, like TDX):

`cargo build -p sgx-verifier-component --release --target wasm32-wasip2`

The resulting component is created at `target/wasm32-wasip2/release/sgx_verifier_component.wasm`.

For ReCFA, the build compiles the vendored upstream C++ verifier, so it needs [wasi-sdk](https://github.com/WebAssembly/wasi-sdk/releases) (>= 24) located via `WASI_SDK_PATH`, `$HOME/wasi-sdk`, or `/opt/wasi-sdk`. Install it once if you have not (25.0 is known good, ~360 MB extracted):

```bash
curl -L https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz \
  | tar -xz -C "$HOME" \
  && mv "$HOME/wasi-sdk-25.0-x86_64-linux" "$HOME/wasi-sdk"
```

Then:

```bash
export WASI_SDK_PATH=$HOME/wasi-sdk
cargo build -p recfa-verifier-component --release --target wasm32-wasip2
```

Setting `WASI_SDK_PATH` does not install anything — if it points at a directory with no `bin/clang++`, `build.rs` panics with `WASI_SDK_PATH=… has no bin/clang++`. This is the only component in the repo that needs a C++ cross-toolchain.

The resulting component is created at `target/wasm32-wasip2/release/recfa_verifier_component.wasm`.

There is also a builder script that validates the component and runs the fixture suite:

`bash recfa-verifier/recfa-verifier-component/scripts/build-recfa-wasm-component.sh --test`

## Sign a verifier component

Use the component signer tool to add TrustMee expiry metadata and sign the component:

`cargo run -p trustmee-component-signer -- sign --component target/wasm32-wasip2/release/snp_verifier_component.wasm --signed-component target/wasm32-wasip2/release/snp_verifier_component.signed.wasm --signature-expires-at 2035-01-01T00:00:00Z --generate-key --private-key-out component.private.pem --public-key-out component.public.pem --trust-store-out component.trust-store.json --valid-until 2035-01-01T00:00:00Z`

To generate a key pair without signing:

`cargo run -p trustmee-component-signer -- generate-key --private-key-out component.private.pem --public-key-out component.public.pem`

For the layered bootloader verifier component (imports TDX verifier interface and exports the same interface):

`cargo build --manifest-path Cargo.toml -p bootloader-verifier-component --release --target wasm32-wasip2`

Then compose bootloader + tdx so only bootloader exports are exposed:

`bash bootloader-verifier/bootloader-verifier-component/scripts/build-bootloader-composed-component.sh`

This script uses `wac`.
Install once if needed:
`cargo install wac-cli`

The composed component is written to:
`target/wasm32-wasip2/release/bootloader_tdx_verifier_component.wasm`.

The Kata policy verifier composes the same way, with a selectable lower layer:

```bash
bash kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh            # stub lower layer (tests)
LOWER=tdx bash kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh  # real TDX lower layer
LOWER=snp bash kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh  # real SNP lower layer
```

The stub build is written to `target/wasm32-wasip2/release/kata_policy_stub_verifier_component.wasm`, the TDX one to `kata_policy_tdx_verifier_component.wasm`.


## Run the verifier (host-side)

For Bootloader + TDX:

Run bootloader verifier test host:

`cargo run -p bootloader-verifier-test -- --component target/wasm32-wasip2/release/bootloader_tdx_verifier_component.wasm --evidence-json bootloader-verifier/test_data/bootloader_evidence.json`

For Intel TDX:

`cargo run -p tdx-verifier-test -- --component target/wasm32-wasip2/release/tdx_verifier_component.wasm --quote tdx-verifier/test_data/tdx_quote.bin`

Optional inputs:

- `--ccel /path/to/ccel.bin`
- `--pccs-url https://api.trustedservices.intel.com` (defaults to Intel PCS)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`
- `--cache-dir <host-dir>` (collateral cache base; a fresh subdirectory is pre-opened to the component as `cache/`)

On verification failure, the component returns JSON like `{"status":"failed","error":"..."}` and the host exits non-zero.

For AMD SEV-SNP:

`cargo run -p snp-verifier-test -- --component target/wasm32-wasip2/release/snp_verifier_component.wasm --evidence-json snp-verifier/test_data/snp_evidence.json`

Optional inputs:

- `--vlek /path/to/vlek.der` (use VLEK instead of VCEK)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`
- `--cache-dir <host-dir>` (VCEK cache base; a fresh subdirectory is pre-opened to the component as `cache/`)

If no VCEK/VLEK is provided, the component will fetch VCEK from AMD KDS using WASI-HTTP.
If the host pre-opens a `cache/` directory for the component, fetched VCEKs are cached there.
Set `SNP_VCEK_DISABLE_CACHE=1` to disable VCEK caching.

For AMD SEV-SNP with host-side crypto (same evidence, same claims; the harness provides the `snp-host-crypto-interface` import):

`cargo run -p snp-verifier-host-crypto-test --release -- --component target/wasm32-wasip2/release/snp_verifier_host_crypto_component.wasm --evidence-json snp-verifier/test_data/snp_evidence.json`

It accepts `--report` (raw attestation report) instead of `--evidence-json`, plus the same `--vcek` / `--vlek` / `--expected-report-data-hex` / `--expected-init-data-hash-hex` / `--cache-dir` options as above.

For Intel SGX:

`cargo run -p sgx-verifier-test -- --component target/wasm32-wasip2/release/sgx_verifier_component.wasm --quote sgx-verifier/test_data/sgx_dcap_v3_quote_not_debug.bin`

The committed quote is a real DCAP v3 (ECDSA-P256) quote from an enclave launched
**without** the DEBUG attribute, so its measurements are meaningful. No collateral is
committed with it, so the component fetches collateral from Intel PCS over WASI-HTTP —
this command needs outbound network. Optional inputs:

- `--collateral /path/to/collateral.cbor` (CBOR-encoded dcap-qvl `QuoteCollateralV3`; supplying it skips the PCS fetch)
- `--expected-report-data-hex <hex>` (REPORT_DATA binding)
- `--expected-init-data-hash-hex <hex>` (CONFIGID binding)
- `--cache-dir <host-dir>`

Expected output for that quote (abridged; TCB fields track whatever Intel currently
publishes for this platform):

```json
{"body":{"attributes.flags":"0500000000000000","mr_enclave":"1a818f25391de5c4939ff933175153ade954b3e31ce0b454829086c7b7f68956","mr_signer":"669b80648c2d9c97f32263fa1961f95f83818682d6359758221f0e7acb9584c0",…},"header":{"version":"0300","att_key_type":"0200",…},"tcb_status":"OutOfDateConfigurationNeeded","tee_type":"sgx",…}
```

`attributes.flags` is `0x05` (INIT | MODE64BIT) — the DEBUG bit (`0x02`) is clear, which
is what makes this fixture usable as a production-enclave sample.

Its REPORT_DATA and CONFIGID are both all-zero (nothing was bound into them), so
`--expected-report-data-hex 00` and `--expected-init-data-hash-hex 00` pass — the
component zero-pads the expected value to 64 bytes — while any other value fails closed
with `{"status":"failed","error":"REPORT_DATA is different from that in SGX Quote"}`.

**End-to-end test (SGX).** Run from the repo root:

```bash
cargo test -p sgx-verifier-test          # hermetic fixture checks: no network, no wasm

cargo build -p sgx-verifier-component --release --target wasm32-wasip2 \
  && cargo test -p sgx-verifier-test -- --ignored
```

The default run asserts the committed fixture is still a v3 ECDSA quote over a
non-debug enclave with the recorded MRENCLAVE/MRSIGNER, and that the file is a whole
quote (its `signature_data_len` accounts for the tail) — it catches a fixture that was
swapped or truncated without needing a TEE or a network.

The `--ignored` tests drive the built component through wasmtime and need network to
Intel PCS for collateral (~20 s): one verifies the fixture end-to-end and checks the
returned claims, the other checks that the REPORT_DATA / CONFIGID bindings are enforced
and fail closed on a mismatch. As with ReCFA, the `&&` chaining matters — a stale
`.wasm` left in `target/` from an earlier build would otherwise be tested instead of
your current sources.

For the Kata policy verifier, the full scenario matrix runs against the stub hardware layer, so it needs no live TEE:

```bash
cargo test -p kata-policy-core          # structural-parser unit tests
cargo run -p kata-policy-verifier-test --release -- scenarios \
  --component target/wasm32-wasip2/release/kata_policy_stub_verifier_component.wasm \
  --test-data kata-policy-verifier/test_data
```

Expected output:

```
PASS  (a) valid policy accepted (tdx register)
PASS  (a) valid policy accepted (snp register)
PASS  (b) new image digest accepted with updated images claim
PASS  (c) modified rule -> approved_rule_template=false
PASS  (d) exec allowance surfaces in exec_commands claim
PASS  (e) rule appended after policy_data rejected
PASS  (e) rule smuggled on the policy_data line rejected
PASS  (e) second policy_data assignment rejected
PASS  (f) init-data digest != measured MRCONFIGID rejected
PASS  (g) invalid hardware quote rejected
all scenarios passed
```

A single run, printing the claims:

`cargo run -p kata-policy-verifier-test --release -- run --component target/wasm32-wasip2/release/kata_policy_stub_verifier_component.wasm --evidence-json kata-policy-verifier/test_data/stub-evidence-valid.json --init-data kata-policy-verifier/test_data/initdata.toml --approved-templates kata-policy-verifier/test_data/approved-templates.json`

Against a composed TDX build, swap the component for `kata_policy_tdx_verifier_component.wasm` and pass real TDX evidence. See [kata-policy-verifier/README.md](kata-policy-verifier/README.md) for the endorsement formats and how to regenerate the fixtures.

For ReCFA:

Unlike the TEE verifiers, ReCFA takes no quote. The evidence is the folded control-flow
event stream from the attester, and the reference values (disassembly, CFG, policy F,
policy M, config) are passed as endorsements — nothing is hardcoded in the component.

### End-to-end test (ReCFA)

Run from the repo root. This builds the component and the host harness, then replays
the shipped fixture — a small hand-built program with a known-correct CFG — covering a
direct call, the compressed direct-call encoding, an indirect call, an indirect jump,
policy-M call-site reconstruction, and one case per violation class:

The `&&` chaining matters: `target/` may already hold a component from an earlier build, so
if you let a failed `cargo build` fall through, the suite happily passes against the **stale**
`.wasm` and the green table tells you nothing about your current sources.

```bash
export WASI_SDK_PATH=$HOME/wasi-sdk    # must already contain bin/clang++, see Build above

cargo build -p recfa-verifier-component --release --target wasm32-wasip2 \
  && cargo build -p recfa-verifier-test \
  && ./target/debug/recfa-verifier-test \
    --component   target/wasm32-wasip2/release/recfa_verifier_component.wasm \
    --disassembly recfa-verifier/test_data/prog.asm \
    --cfg         recfa-verifier/test_data/prog.dot \
    --policy-f    recfa-verifier/test_data/binfo.prog \
    --batch       recfa-verifier/test_data \
    --compiler gcc
```

`--batch` runs every `*.trace` in the directory and infers the expected outcome from the
`pass_`/`fail_` filename prefix, picking up a same-named `.map` as policy M when present.
The vendored verifier keeps upstream's progress writes to stdout (`|M|= …`, `Nevents sucess`),
so expect that noise interleaved with the table; the verdict is carried entirely in the
returned JSON. The last lines should be:

```
CASE               VERDICT                    EVENTS   RESULT
fail_icall         indirect-call-violation    2        OK
fail_ijmp          indirect-jump-violation    2        OK
fail_shadow        shadow-stack-violation     3        OK
pass_compressed    secure                     5        OK
pass_icall         secure                     9        OK
pass_ijmp          secure                     3        OK
pass_policy_m      secure                     11       OK
pass_simple        secure                     5        OK

PASS: all 8 cases behaved as expected
```

To evaluate a single trace and print the claims JSON, replace `--batch` with `--trace`:

`./target/debug/recfa-verifier-test --component target/wasm32-wasip2/release/recfa_verifier_component.wasm --disassembly recfa-verifier/test_data/prog.asm --cfg recfa-verifier/test_data/prog.dot --policy-f recfa-verifier/test_data/binfo.prog --trace recfa-verifier/test_data/pass_simple.trace --compiler gcc`

Optional inputs:

- `--policy-m /path/to/*.filtered.map` (skipped direct call sites; omitting it means no call-site filtering)
- `--compiler gcc|llvm` (selects the indirect-jump register the disassembly regex matches; the wrong value silently drops every indirect jump from the policy)
- `--num-executions N` (must match how many runs of `main` the trace contains)
- `--bind-report-data` / `--bind-wrong-report-data` (checks that `expected-report-data` is bound to `sha256(evidence)` and fails closed when it does not match)
- `--expect secure|failed` (assert the outcome, for use as a test)
- `--cache-dir <host-dir>` (a fresh subdirectory is pre-opened to the component as `cache/`; the component does not otherwise need a filesystem)

On a CFI violation the component fails closed and names the offending edge, e.g.
`{"status":"failed","error":"indirect-call-violation at 0x401020: target 0x401100 is not permitted"}`,
and the host exits non-zero.

For a full attester-to-verifier run on a program written for this repo — compiled,
statically instrumented with Dyninst, executed, and verified from the events that run
recorded, with policy F generated by the patched typearmor pass — see
[recfa-verifier/custom-e2e/](recfa-verifier/custom-e2e/):

```bash
bash recfa-verifier/custom-e2e/build.sh --test
```

It builds the two attester toolchains as containers, regenerates every artifact, and
runs two end-to-end tests against the component: the untampered run verifies, and the
`make-tamper.py` hijack is rejected with the offending edge named.

`recfa-verifier/README.md` also documents a parity harness that compares the vendored
verifier against unmodified upstream `check`, and a run against real SPEC CPU2006
attester output. Both need inputs that are not committed (upstream ReCFA checked out,
and the 10.8 MB bzip2 trace plus a Dyninst-generated `.dot`) — see
`recfa-verifier/ATTESTER_SETUP.md`.

## Check the host contains a hostile component

`infinite-loop-verifier-component` is not a verifier: its `evaluate` is `loop {}`. It
ships no test harness on purpose — build it and point your own host at it, which should
interrupt the guest (wasmtime fuel or epoch interruption) instead of hanging. A host that
hangs here will hang on any untrusted component.

`cargo build -p infinite-loop-verifier-component --release --target wasm32-wasip2`
