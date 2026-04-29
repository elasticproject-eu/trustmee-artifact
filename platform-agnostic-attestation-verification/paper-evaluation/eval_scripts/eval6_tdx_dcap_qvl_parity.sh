#!/usr/bin/env bash
# Eval 6: native TDX verifier via dcap-qvl crate vs wasm TDX verifier
# (verifier-only time). Collateral fetch is excluded from both via
# DCAP_QVL_CACHE_DIR warm cache + CMW collateral on wasm side.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

TDX_NATIVE_BODY="$TMP_DIR/eval6_tdx_native.body.json"
TDX_WASM_BODY="$TMP_DIR/eval6_tdx_wasm.body.json"
TDX_WASM_WARMUP_BODY="$TMP_DIR/eval6_tdx_wasm.warmup.body.json"

build_tdx_native_body "$TDX_NATIVE_BODY"
build_tdx_wasm_body "$TDX_WASM_BODY" 1 component-id
build_tdx_wasm_body "$TDX_WASM_WARMUP_BODY" 1 component

DCAP_CACHE="$TMP_DIR/eval6_dcap_qvl_cache"
rm -rf "$DCAP_CACHE"
mkdir -p "$DCAP_CACHE"

echo "-- TDX native via dcap-qvl --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export TDX_NATIVE_USE_DCAP_QVL=1
  export DCAP_QVL_CACHE_DIR="$DCAP_CACHE"
  start_as
  run_latency "$TDX_NATIVE_BODY" "$RESULTS_DIR/eval6_tdx_native_e2e.json" --warmup 2
  stop_as
  save_log "$RESULTS_DIR/logs/eval6_tdx_native.log"
)

python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
  --log "$RESULTS_DIR/logs/eval6_tdx_native.log" \
  --event as_verifier_timing \
  --tee Tdx \
  --mode native \
  --skip 2 \
  --output "$RESULTS_DIR/eval6_tdx_native_verifier_dcap_qvl.json"

echo "-- TDX wasm (same dcap-qvl, CMW collateral) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  start_as
  run_wasm_latency "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval6_tdx_wasm_e2e.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval6_tdx_wasm.log"
)

parse_as_verifier_timing_with_fallback \
  "$RESULTS_DIR/logs/eval6_tdx_wasm.log" \
  wasm \
  1 \
  "$RESULTS_DIR/eval6_tdx_wasm_verifier_dcap_qvl.json" \
  Tdx \
  Sample
