# Shared environment + helpers sourced by every eval_scripts/eval*.sh.
# Callers set variables before sourcing; the helpers honor them.
#
# Required variables set by run_all.sh before sourcing:
#   REPO_ROOT         platform-agnostic-attestation-verification/ absolute path
#   WORKSPACE_ROOT    parent directory containing sibling repos
#   PAPER_EVAL_ROOT   paper-evaluation/ absolute path
#   RESULTS_DIR       this run's timestamped output directory
#   RUNS              number of measurement iterations (default 50)
#   PORT              restful-as port (default 18080)
#   TMP_DIR           scratch dir for AS config/logs

set -eo pipefail

: "${REPO_ROOT:?REPO_ROOT not set}"
: "${WORKSPACE_ROOT:?WORKSPACE_ROOT not set}"
: "${PAPER_EVAL_ROOT:?PAPER_EVAL_ROOT not set}"
: "${RESULTS_DIR:?RESULTS_DIR not set}"
: "${PORT:=18080}"
: "${RUNS:=50}"
: "${TMP_DIR:=$PAPER_EVAL_ROOT/tmp}"

# Paper evals default to the warm Wasm verifier cache: loaded/pre-instantiated
# components are cached in memory, but each request gets a fresh instance. The
# cold evals still set TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1, and the one
# cold/warm/hot comparison explicitly overrides this to `hot`.
export TRUSTMEE_WASM_INMEM_CACHE_MODE=warm

BIN_DIR="$PAPER_EVAL_ROOT/bin"
ATTESTATION_URL="http://127.0.0.1:${PORT}/attestation"
ATTESTATION_INPUT_CLI="$WORKSPACE_ROOT/attestation-input-for-trustmee/target/release/attestation-input-format"
FETCH_TDX_COLLATERAL_CLI="$REPO_ROOT/paper-evaluation/tools/fetch-tdx-collateral/target/release/fetch-tdx-collateral"
WASMTIME_COMPILE_BENCH_CLI="$REPO_ROOT/paper-evaluation/tools/wasmtime-compile-bench/target/release/wasmtime-compile-bench"
RESTFUL_BIN="$REPO_ROOT/target/release/restful-as"
WASM_TARGET_ROOT="$WORKSPACE_ROOT/wasm-verification-components/target/wasm32-wasip2/release"
SNP_WASM="$WASM_TARGET_ROOT/snp_verifier_component.wasm"
SNP_WASM_HOST="$WASM_TARGET_ROOT/snp_verifier_host_crypto_component.wasm"
SGX_WASM="$WASM_TARGET_ROOT/sgx_verifier_component.wasm"
TDX_WASM="$WASM_TARGET_ROOT/tdx_verifier_component.wasm"
SNP_EVIDENCE="$REPO_ROOT/test_data/trustmee-lib/snp_evidence.json"
SNP_EVIDENCE_NO_CHAIN="$TMP_DIR/snp_evidence_no_chain.json"
SGX_QUOTE="$REPO_ROOT/test_data/trustmee-lib/sgx_dcap_v3_quote_not_debug.bin"
TDX_QUOTE="$REPO_ROOT/test_data/trustmee-lib/tdx_quote.bin"
TDX_COLLATERAL_CBOR="$TMP_DIR/tdx_collateral.cbor"
SGX_COLLATERAL_CBOR="$TMP_DIR/sgx_collateral.cbor"
SNP_CERT_CHAIN_CBOR="$TMP_DIR/snp_cert_chain.cbor"

mkdir -p "$TMP_DIR"
export PYTHONPATH="$BIN_DIR${PYTHONPATH:+:$PYTHONPATH}"

# Start the AS with the currently exported env. The caller is expected to
# export whichever paper-eval knobs it needs (AS_VERIFICATION_TIMING_JSON etc)
# BEFORE calling start_as.
start_as() {
  stop_as >/dev/null 2>&1 || true
  LOG_PATH="$TMP_DIR/restful-as.log" \
  PID_PATH="$TMP_DIR/restful-as.pid" \
  PORT="$PORT" \
  TMP_DIR="$TMP_DIR" \
  WORK_DIR="$TMP_DIR/work" \
  RESTFUL_BIN="$RESTFUL_BIN" \
  RUST_LOG="${RUST_LOG:-info}" \
  bash "$BIN_DIR/start_restful_as.sh"
}

stop_as() {
  TMP_DIR="$TMP_DIR" \
  PID_PATH="$TMP_DIR/restful-as.pid" \
  bash "$BIN_DIR/stop_restful_as.sh"
}

cleanup_as() {
  stop_as >/dev/null 2>&1 || true
}

trap cleanup_as EXIT
trap 'cleanup_as; exit 130' INT
trap 'cleanup_as; exit 143' TERM

# Copy the AS log out to results dir after each eval for parse_timings.py.
save_log() {
  local dest="$1"
  cp "$TMP_DIR/restful-as.log" "$dest"
}

# Trustee-compatible CMW requests enter the AS as Tee::Sample until the Wasm
# component returns platform claims, while older runs logged Snp/Tdx directly.
parse_as_verifier_timing_with_fallback() {
  local log="$1"
  local mode="$2"
  local skip="$3"
  local output="$4"
  shift 4

  local tee count
  for tee in "$@"; do
    python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
      --log "$log" \
      --event as_verifier_timing \
      --tee "$tee" \
      --mode "$mode" \
      --skip "$skip" \
      --output "$output" >/dev/null

    count="$(python3 - "$output" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
print(int(data.get("ms", {}).get("count", 0)))
PY
)"
    if [[ "$count" -gt 0 ]]; then
      return 0
    fi
  done
  return 0
}

# Sample endorsement for SNP: the cert_chain already inlined in
# snp_evidence.json serialised as CBOR. We take a shortcut: the
# `attestation-input-for-trustmee` CLI already accepts endorsement paths,
# so this helper just writes the CBOR payload once.
ensure_snp_cert_chain_cbor() {
  if [[ -f "$SNP_CERT_CHAIN_CBOR" ]]; then
    return
  fi
  python3 "$BIN_DIR/extract_snp_cert_chain_cbor.py" \
    --evidence "$SNP_EVIDENCE" \
    --output "$SNP_CERT_CHAIN_CBOR"
}

# The SNP wasm component refuses to accept a cert-chain endorsement if the
# evidence JSON *also* has cert_chain. For evals that put the cert chain in
# the CMW we first strip it from the evidence copy. Keep the stripped evidence
# compact so size measurements are not dominated by formatting whitespace that
# gets amplified by the CMW/EAT encodings.
ensure_snp_evidence_no_chain() {
  python3 - <<PY
import json
ev = json.load(open("$SNP_EVIDENCE"))
ev.pop("cert_chain", None)
with open("$SNP_EVIDENCE_NO_CHAIN", "w") as f:
    json.dump(ev, f, separators=(",", ":"))
PY
}

ensure_tdx_collateral_cbor() {
  if [[ -f "$TDX_COLLATERAL_CBOR" ]]; then
    return
  fi
  "$FETCH_TDX_COLLATERAL_CLI" \
    --quote "$TDX_QUOTE" \
    --output "$TDX_COLLATERAL_CBOR"
}

ensure_sgx_collateral_cbor() {
  if [[ -f "$SGX_COLLATERAL_CBOR" ]]; then
    return
  fi
  "$FETCH_TDX_COLLATERAL_CLI" \
    --quote "$SGX_QUOTE" \
    --output "$SGX_COLLATERAL_CBOR"
}

component_id_for() {
  local component="$1"
  local digest
  digest="$(sha256sum "$component" | cut -d ' ' -f 1)"
  printf 'component-%s' "$digest"
}

build_snp_wasm_body() {
  local component="$1"
  local output="$2"
  local with_collateral="$3"   # 0 = force KDS fetch, 1 = CMW-embedded cert chain
  local component_mode="${4:-component}"  # component = staple bytes, component-id = reference cache
  # Always strip cert_chain from the SNP evidence so the wasm verifier's cert
  # source is controlled purely by the CMW endorsement. with_collateral=0 ⇒
  # no endorsement ⇒ the component MUST hit KDS. with_collateral=1 ⇒
  # endorsement carries a stapled CBOR cert chain ⇒ component skips KDS.
  ensure_snp_evidence_no_chain
  local evidence="$SNP_EVIDENCE_NO_CHAIN"
  local args=(
    --attestation-input-cli "$ATTESTATION_INPUT_CLI"
    --cmw-format "${TRUSTMEE_CMW_FORMAT:-cbor}"
    --tee snp
    --evidence "$evidence"
    --output "$output"
  )
  if [[ "$component_mode" == "component-id" ]]; then
    args+=(--component-id "$(component_id_for "$component")")
  elif [[ "$component_mode" == "component" ]]; then
    args+=(--component "$component")
  else
    echo "unknown component mode: $component_mode" >&2
    return 2
  fi
  if [[ "$with_collateral" == "1" ]]; then
    ensure_snp_cert_chain_cbor
    args+=(--endorsement "snp-collateral:application/vnd.trustmee.snp-collateral+cbor:$SNP_CERT_CHAIN_CBOR")
  fi
  python3 "$BIN_DIR/build_cmw.py" "${args[@]}"
}

build_tdx_wasm_body() {
  local output="$1"
  local with_collateral="$2"   # 0/1
  local component_mode="${3:-component}"  # component = staple bytes, component-id = reference cache
  local args=(
    --attestation-input-cli "$ATTESTATION_INPUT_CLI"
    --cmw-format "${TRUSTMEE_CMW_FORMAT:-cbor}"
    --tee tdx
    --evidence "$TDX_QUOTE"
    --output "$output"
  )
  if [[ "$component_mode" == "component-id" ]]; then
    args+=(--component-id "$(component_id_for "$TDX_WASM")")
  elif [[ "$component_mode" == "component" ]]; then
    args+=(--component "$TDX_WASM")
  else
    echo "unknown component mode: $component_mode" >&2
    return 2
  fi
  if [[ "$with_collateral" == "1" ]]; then
    ensure_tdx_collateral_cbor
    args+=(--endorsement "tdx-collateral:application/vnd.trustmee.tdx-collateral+cbor:$TDX_COLLATERAL_CBOR")
  fi
  python3 "$BIN_DIR/build_cmw.py" "${args[@]}"
}

build_sgx_wasm_body() {
  local output="$1"
  local with_collateral="$2"   # 0/1
  local component_mode="${3:-component}"  # component = staple bytes, component-id = reference cache
  local args=(
    --attestation-input-cli "$ATTESTATION_INPUT_CLI"
    --cmw-format "${TRUSTMEE_CMW_FORMAT:-cbor}"
    --tee sgx
    --evidence "$SGX_QUOTE"
    --output "$output"
  )
  if [[ "$component_mode" == "component-id" ]]; then
    args+=(--component-id "$(component_id_for "$SGX_WASM")")
  elif [[ "$component_mode" == "component" ]]; then
    args+=(--component "$SGX_WASM")
  else
    echo "unknown component mode: $component_mode" >&2
    return 2
  fi
  if [[ "$with_collateral" == "1" ]]; then
    ensure_sgx_collateral_cbor
    args+=(--endorsement "sgx-collateral:application/vnd.trustmee.sgx-collateral+cbor:$SGX_COLLATERAL_CBOR")
  fi
  python3 "$BIN_DIR/build_cmw.py" "${args[@]}"
}

build_snp_native_body() {
  local output="$1"
  local include_cert_chain="$2"  # 0/1
  local args=(--evidence "$SNP_EVIDENCE" --output "$output")
  if [[ "$include_cert_chain" == "0" ]]; then
    args+=(--no-cert-chain)
  fi
  python3 "$BIN_DIR/build_snp_native_body.py" "${args[@]}"
}

build_tdx_native_body() {
  local output="$1"
  python3 "$BIN_DIR/build_tdx_native_body.py" \
    --quote "$TDX_QUOTE" \
    --output "$output"
}

build_sgx_native_body() {
  local output="$1"
  python3 "$BIN_DIR/build_sgx_native_body.py" \
    --quote "$SGX_QUOTE" \
    --output "$output"
}

run_latency() {
  local body_file="$1"
  local output="$2"
  local output_base
  local attestation_result_log
  shift 2
  output_base="$(basename "${output%.json}")"
  attestation_result_log="$RESULTS_DIR/logs/${output_base}_attestation_result.json"
  python3 "$BIN_DIR/eval_latency.py" \
    --url "$ATTESTATION_URL" \
    --body-file "$body_file" \
    --runs "$RUNS" \
    --output "$output" \
    --attestation-result-log "$attestation_result_log" \
    "$@"
}

run_wasm_latency() {
  local body_file="$1"
  local warmup_body_file="$2"
  local output="$3"
  shift 3
  run_latency "$body_file" "$output" \
    --warmup 1 \
    --warmup-body-file "$warmup_body_file" \
    "$@"
}

parse_timing() {
  local event="$1"
  local output="$2"
  shift 2
  python3 "$BIN_DIR/parse_timings.py" \
    --log "$TMP_DIR/restful-as.log" \
    --event "$event" \
    --output "$output" \
    "$@"
}
