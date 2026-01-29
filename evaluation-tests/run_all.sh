#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT_DIR/evaluation-tests/bin"
RESULTS_BASE_DIR="${RESULTS_DIR:-$ROOT_DIR/evaluation-tests/results}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S%z)}"
RESULTS_DIR="$RESULTS_BASE_DIR/$RUN_ID"
ATTESTATION_LOG_DIR="${ATTESTATION_LOG_DIR:-$ROOT_DIR/evaluation-tests/attestation-results}"
TMP_DIR="${TMP_DIR:-$ROOT_DIR/evaluation-tests/tmp}"
PORT="${PORT:-18080}"
AS_URL="http://127.0.0.1:${PORT}/attestation"
COMPONENT_URL="http://127.0.0.1:${PORT}/component"
WASM_WORK_DIR="${WASM_WORK_DIR:-/tmp/as-eval-wasm}"
WASM_CACHE_DIR="${WASM_CACHE_DIR:-$WASM_WORK_DIR/wasm-cache}"

if [[ -n "${NATIVE_OPENSSL_DIR:-}" ]]; then
  OPENSSL_LIB_DIR="$NATIVE_OPENSSL_DIR/lib64"
  if [[ ! -d "$OPENSSL_LIB_DIR" ]]; then
    OPENSSL_LIB_DIR="$NATIVE_OPENSSL_DIR/lib"
  fi
  if [[ -d "$OPENSSL_LIB_DIR" ]]; then
    export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
fi

mkdir -p "$RESULTS_DIR" "$ATTESTATION_LOG_DIR" "$TMP_DIR"

write_system_info() {
  local out="$1"
  {
    echo "timestamp: $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "run_id: $RUN_ID"
    echo "hostname: $(hostname)"
    echo "kernel: $(uname -a)"
    echo
    echo "os_release:"
    if [[ -f /etc/os-release ]]; then
      cat /etc/os-release
    else
      echo "missing /etc/os-release"
    fi
    echo
    echo "cpu:"
    if command -v lscpu >/dev/null 2>&1; then
      lscpu
    elif [[ -f /proc/cpuinfo ]]; then
      cat /proc/cpuinfo
    else
      echo "cpu info not available"
    fi
    echo
    echo "memory:"
    if command -v free >/dev/null 2>&1; then
      free -h
    elif [[ -f /proc/meminfo ]]; then
      cat /proc/meminfo
    else
      echo "memory info not available"
    fi
  } > "$out"
}

SYSTEM_INFO_PATH="$RESULTS_DIR/system_info.txt"
write_system_info "$SYSTEM_INFO_PATH"

run_latency() {
  local tee="$1"
  local mode="$2"
  local out="$3"
  shift 3
  local base="${out##*/}"
  local result_log="$ATTESTATION_LOG_DIR/${base%.json}_attestation.jsonl"
  local dump_arg=()
  if [[ -n "${DUMP_REQUEST:-}" ]]; then
    dump_arg=(--dump-request "$DUMP_REQUEST")
  fi
  python3 "$BIN_DIR/eval_latency.py" \
    --url "$AS_URL" \
    --tee "$tee" \
    --runs 1 \
    --output "$out" \
    --result-log "$result_log" \
    "${dump_arg[@]}" \
    "$@"
}

parse_verifier_timing() {
  local log_path="$1"
  local tee="$2"
  local mode="$3"
  local out="$4"
  python3 "$BIN_DIR/parse_timings.py" \
    --log "$log_path" \
    --event as_verifier_timing \
    --tee "$tee" \
    --mode "$mode" \
    --output "$out"
}

parse_collateral_timing() {
  local log_path="$1"
  local tee="$2"
  local mode="$3"
  local out="$4"
  python3 "$BIN_DIR/parse_timings.py" \
    --log "$log_path" \
    --event as_tdx_collateral_timing \
    --tee "$tee" \
    --mode "$mode" \
    --fields ms \
    --output "$out"
}

parse_snp_steps() {
  local log_path="$1"
  local mode="$2"
  local out="$3"
  python3 "$BIN_DIR/parse_timings.py" \
    --log "$log_path" \
    --event snp_step_timing \
    --mode "$mode" \
    --output "$out"
}

run_resources() {
  local tee="$1"
  local pid="$2"
  local out="$3"
  shift 3
  python3 "$BIN_DIR/eval_resources.py" \
    --pid "$pid" \
    --samples 1 \
    --interval 1 \
    --url "$AS_URL" \
    --tee "$tee" \
    --output "$out" \
    "$@"
}

echo "== build artifacts =="
"$BIN_DIR/build_artifacts.sh"

echo "== SNP native =="
SNP_STEP_TIMING_JSON=1 SNP_TIMING_MODE=native AS_VERIFICATION_TIMING_JSON=1 \
  PORT="$PORT" TMP_DIR="$TMP_DIR" "$BIN_DIR/start_restful_as.sh" native
NATIVE_LOG="$TMP_DIR/restful-as-native.log"
PID="$(cat "$TMP_DIR/restful-as-native.pid")"
run_latency snp native "$RESULTS_DIR/snp_native_latency.json"
parse_verifier_timing "$NATIVE_LOG" "Snp" "native" "$RESULTS_DIR/snp_native_verifier_time.json"
parse_snp_steps "$NATIVE_LOG" "native" "$RESULTS_DIR/snp_native_step_breakdown.json"
run_latency snp native "$RESULTS_DIR/snp_native_latency_no_cert.json" \
  --no-cert-chain --interval 5 --max-retries 10 --retry-initial 2 --retry-backoff 1.5
run_resources snp "$PID" "$RESULTS_DIR/snp_native_resources.json"
"$BIN_DIR/stop_restful_as.sh" native

echo "== SNP wasm =="
SNP_STEP_TIMING_JSON=1 SNP_TIMING_MODE=wasm AS_VERIFICATION_TIMING_JSON=1 \
  PORT="$PORT" TMP_DIR="$TMP_DIR" WORK_DIR="$WASM_WORK_DIR" "$BIN_DIR/start_restful_as.sh" wasm
WASM_LOG="$TMP_DIR/restful-as-wasm.log"
PID="$(cat "$TMP_DIR/restful-as-wasm.pid")"
SNP_COMPONENT_ID="$(
  python3 "$BIN_DIR/register_component.py" \
    --url "$COMPONENT_URL" \
    --component "$ROOT_DIR/target/wasm32-wasip2/release/snp_verifier_component.wasm"
)"
run_latency snp wasm "$RESULTS_DIR/snp_wasm_latency.json" --component-id "$SNP_COMPONENT_ID"
parse_verifier_timing "$WASM_LOG" "Snp" "wasm" "$RESULTS_DIR/snp_wasm_verifier_time.json"
parse_snp_steps "$WASM_LOG" "wasm" "$RESULTS_DIR/snp_wasm_step_breakdown.json"
run_latency snp wasm "$RESULTS_DIR/snp_wasm_latency_no_cert.json" \
  --no-cert-chain --component-id "$SNP_COMPONENT_ID" \
  --interval 5 --max-retries 10 --retry-initial 2 --retry-backoff 1.5
run_resources snp "$PID" "$RESULTS_DIR/snp_wasm_resources.json" --component-id "$SNP_COMPONENT_ID"
"$BIN_DIR/stop_restful_as.sh" wasm

echo "== TDX native =="
AS_VERIFICATION_TIMING_JSON=1 PORT="$PORT" TMP_DIR="$TMP_DIR" "$BIN_DIR/start_restful_as.sh" native
NATIVE_LOG="$TMP_DIR/restful-as-native.log"
PID="$(cat "$TMP_DIR/restful-as-native.pid")"
run_latency tdx native "$RESULTS_DIR/tdx_native_latency.json" \
  --timeout 180 --max-retries 5 --retry-initial 2 --retry-backoff 1.5
parse_verifier_timing "$NATIVE_LOG" "Tdx" "native" "$RESULTS_DIR/tdx_native_verifier_time.json"
parse_collateral_timing "$NATIVE_LOG" "Tdx" "native" "$RESULTS_DIR/tdx_native_collateral_time.json"
run_resources tdx "$PID" "$RESULTS_DIR/tdx_native_resources.json"
"$BIN_DIR/stop_restful_as.sh" native

echo "== TDX wasm =="
AS_VERIFICATION_TIMING_JSON=1 PORT="$PORT" TMP_DIR="$TMP_DIR" WORK_DIR="$WASM_WORK_DIR" \
  "$BIN_DIR/start_restful_as.sh" wasm
WASM_LOG="$TMP_DIR/restful-as-wasm.log"
PID="$(cat "$TMP_DIR/restful-as-wasm.pid")"
TDX_COMPONENT_ID="$(
  python3 "$BIN_DIR/register_component.py" \
    --url "$COMPONENT_URL" \
    --component "$ROOT_DIR/target/wasm32-wasip2/release/tdx_verifier_component.wasm"
)"
run_latency tdx wasm "$RESULTS_DIR/tdx_wasm_latency.json" --component-id "$TDX_COMPONENT_ID" \
  --timeout 180 --max-retries 5 --retry-initial 2 --retry-backoff 1.5
parse_verifier_timing "$WASM_LOG" "Tdx" "wasm" "$RESULTS_DIR/tdx_wasm_verifier_time.json"
parse_collateral_timing "$WASM_LOG" "Tdx" "wasm" "$RESULTS_DIR/tdx_wasm_collateral_time.json"
run_resources tdx "$PID" "$RESULTS_DIR/tdx_wasm_resources.json" --component-id "$TDX_COMPONENT_ID"
"$BIN_DIR/stop_restful_as.sh" wasm

echo "== TDX native (dcap-qvl for fig26) =="
AS_VERIFICATION_TIMING_JSON=1 TDX_NATIVE_USE_DCAP_QVL=1 DCAP_QVL_CACHE_DIR="$WASM_CACHE_DIR" \
  PORT="$PORT" TMP_DIR="$TMP_DIR" "$BIN_DIR/start_restful_as.sh" native
NATIVE_LOG="$TMP_DIR/restful-as-native.log"
PID="$(cat "$TMP_DIR/restful-as-native.pid")"
run_latency tdx native "$RESULTS_DIR/tdx_native_latency_dcap_qvl.json" \
  --timeout 180 --max-retries 5 --retry-initial 2 --retry-backoff 1.5
parse_verifier_timing "$NATIVE_LOG" "Tdx" "native" "$RESULTS_DIR/tdx_native_verifier_time_dcap_qvl.json"
"$BIN_DIR/stop_restful_as.sh" native

echo "== generate figures =="
python3 "$BIN_DIR/plot_figures.py" --results-dir "$RESULTS_DIR" --preset evaluation-all

echo "results written to: $RESULTS_DIR"
echo "system info written to: $SYSTEM_INFO_PATH"
echo "attestation logs written to: $ATTESTATION_LOG_DIR"
