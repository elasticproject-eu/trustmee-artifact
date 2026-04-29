#!/usr/bin/env bash
# Eval 3: impact of the in-memory wasm verifier cache. All series include
# collateral in the CMW so only the cache effect varies.
#
# Emits two figures' worth of data:
#   * E2E latency (client side, via eval_latency.py) — cold vs warm vs hot
#   * AS-verifier span (as_verifier_timing) — cold vs warm vs hot, i.e. the
#     verifier.evaluate(...) time inside the AS, excluding HTTP+framework
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

SNP_WASM_BODY="$TMP_DIR/eval3_snp_wasm.body.json"
SNP_WASM_WARMUP_BODY="$TMP_DIR/eval3_snp_wasm.warmup.body.json"
TDX_WASM_BODY="$TMP_DIR/eval3_tdx_wasm.body.json"
TDX_WASM_WARMUP_BODY="$TMP_DIR/eval3_tdx_wasm.warmup.body.json"

build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_BODY" 1 component-id
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_WARMUP_BODY" 1 component
build_tdx_wasm_body "$TDX_WASM_BODY" 1 component-id
build_tdx_wasm_body "$TDX_WASM_WARMUP_BODY" 1 component

run_and_parse() {
  local label="$1" body="$2" warmup_body="$3" tee_cap="$4" e2e_out="$5" asv_out="$6" log_name="$7"
  shift 7
  local log_path="$RESULTS_DIR/logs/${log_name}.log"
  echo "-- $label --"
  start_as
  run_wasm_latency "$body" "$warmup_body" "$e2e_out" "$@"
  stop_as
  save_log "$log_path"
  parse_as_verifier_timing_with_fallback \
    "$log_path" wasm 1 "$asv_out" "$tee_cap" Sample
}

(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  run_and_parse "SNP wasm cold (in-memory cache disabled)" \
    "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" "Snp" \
    "$RESULTS_DIR/eval3_snp_wasm_latency_cold.json" \
    "$RESULTS_DIR/eval3_snp_wasm_verifier_cold.json" \
    "eval3_snp_wasm_cold"
)

(
  export AS_VERIFICATION_TIMING_JSON=1
  run_and_parse "SNP wasm warm (pre-instantiated verifier cache)" \
    "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" "Snp" \
    "$RESULTS_DIR/eval3_snp_wasm_latency_warm.json" \
    "$RESULTS_DIR/eval3_snp_wasm_verifier_warm.json" \
    "eval3_snp_wasm_warm"
)

(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_INMEM_CACHE_MODE=hot
  run_and_parse "SNP wasm hot (instantiated verifier cache)" \
    "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" "Snp" \
    "$RESULTS_DIR/eval3_snp_wasm_latency_hot.json" \
    "$RESULTS_DIR/eval3_snp_wasm_verifier_hot.json" \
    "eval3_snp_wasm_hot"
)

(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  run_and_parse "TDX wasm cold" \
    "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" "Tdx" \
    "$RESULTS_DIR/eval3_tdx_wasm_latency_cold.json" \
    "$RESULTS_DIR/eval3_tdx_wasm_verifier_cold.json" \
    "eval3_tdx_wasm_cold"
)

(
  export AS_VERIFICATION_TIMING_JSON=1
  run_and_parse "TDX wasm warm" \
    "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" "Tdx" \
    "$RESULTS_DIR/eval3_tdx_wasm_latency_warm.json" \
    "$RESULTS_DIR/eval3_tdx_wasm_verifier_warm.json" \
    "eval3_tdx_wasm_warm"
)

(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_INMEM_CACHE_MODE=hot
  run_and_parse "TDX wasm hot" \
    "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" "Tdx" \
    "$RESULTS_DIR/eval3_tdx_wasm_latency_hot.json" \
    "$RESULTS_DIR/eval3_tdx_wasm_verifier_hot.json" \
    "eval3_tdx_wasm_hot"
)
