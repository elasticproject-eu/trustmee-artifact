#!/usr/bin/env bash
# Eval 7: E2E latency WITH collateral fetch (all caches disabled).
#
# - SNP native: strip cert_chain => verifier hits KDS. SNP_VCEK_DISABLE_CACHE=1.
# - SNP wasm:   CMW has no snp-collateral endorsement => component hits KDS.
#               Every measured request carries and uses stapled wasm bytes.
# - TDX native: original libsgx-dcap path (TDX_NATIVE_USE_DCAP_QVL not set).
#               DCAP_QVL_DISABLE_CACHE=1 to bypass dcap-qvl-wasi's cache
#               (applies to the native dcap-qvl-wasi not used here but kept
#               for consistency).
# - TDX wasm:   no CMW collateral; component must fetch from PCS.
#               DCAP_QVL_DISABLE_CACHE=1. Every measured request carries and
#               uses stapled wasm bytes.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

SNP_NATIVE_BODY="$TMP_DIR/eval7_snp_native.body.json"
SNP_WASM_BODY="$TMP_DIR/eval7_snp_wasm.body.json"
TDX_NATIVE_BODY="$TMP_DIR/eval7_tdx_native.body.json"
TDX_WASM_BODY="$TMP_DIR/eval7_tdx_wasm.body.json"

build_snp_native_body "$SNP_NATIVE_BODY" 0
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_BODY" 0 component
build_tdx_native_body "$TDX_NATIVE_BODY"
build_tdx_wasm_body "$TDX_WASM_BODY" 0 component

# Extra retry/backoff for AMD KDS + Intel PCS rate limits. Override via env
# if the defaults still trigger 429s (AMD KDS is particularly aggressive).
: "${EVAL7_INTERVAL:=10}"
: "${EVAL7_MAX_RETRIES:=12}"
: "${EVAL7_RETRY_INITIAL:=3}"
: "${EVAL7_RETRY_BACKOFF:=2.0}"
RETRY_ARGS=(
  --max-retries "$EVAL7_MAX_RETRIES"
  --retry-initial "$EVAL7_RETRY_INITIAL"
  --retry-backoff "$EVAL7_RETRY_BACKOFF"
  --interval "$EVAL7_INTERVAL"
)

echo "-- SNP native (KDS, no cache) --"
(
  export SNP_VCEK_DISABLE_CACHE=1
  start_as
  run_latency "$SNP_NATIVE_BODY" "$RESULTS_DIR/eval7_snp_native_latency.json" "${RETRY_ARGS[@]}"
  stop_as
  save_log "$RESULTS_DIR/logs/eval7_snp_native.log"
)

echo "-- SNP wasm (KDS fresh per request, no wasm caches) --"
# Remove any stale VCEK disk cache left behind by previous evals so the
# warmup request also truly hits KDS, not a cached VCEK.
rm -rf "$TMP_DIR/work/components/"*/snp-vcek 2>/dev/null || true
(
  export TRUSTMEE_ALLOW_UNSIGNED_NETWORK=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export TRUSTMEE_WASM_DISABLE_COMPONENT_FILE_CACHE=1
  export TRUSTMEE_WASM_DISABLE_WASMTIME_CACHE=1
  # Forwarded into the wasm sandbox — disables the component's VCEK disk
  # cache so every request (including warmup) hits AMD KDS.
  export SNP_VCEK_DISABLE_CACHE=1
  # The CMW includes the wasm component in every measured request. All wasm
  # component memory/file caches are disabled, so those stapled bytes are used.
  start_as
  run_latency "$SNP_WASM_BODY" "$RESULTS_DIR/eval7_snp_wasm_latency.json" \
    --warmup 1 "${RETRY_ARGS[@]}"
  stop_as
  save_log "$RESULTS_DIR/logs/eval7_snp_wasm.log"
)

echo "-- TDX native (original libsgx, no cache) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export DCAP_QVL_DISABLE_CACHE=1
  # TDX_NATIVE_USE_DCAP_QVL intentionally not set: this eval uses the original
  # intel-tee-quote-verification-rs path.
  start_as
  run_latency "$TDX_NATIVE_BODY" "$RESULTS_DIR/eval7_tdx_native_latency.json" "${RETRY_ARGS[@]}"
  stop_as
  save_log "$RESULTS_DIR/logs/eval7_tdx_native.log"
)

echo "-- TDX wasm (PCS fresh per request, no wasm caches) --"
(
  export TRUSTMEE_ALLOW_UNSIGNED_NETWORK=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export TRUSTMEE_WASM_DISABLE_COMPONENT_FILE_CACHE=1
  export TRUSTMEE_WASM_DISABLE_WASMTIME_CACHE=1
  # Forwarded into wasm; dcap-qvl-wasi honors this to skip its JSON cache.
  export DCAP_QVL_DISABLE_CACHE=1
  # The CMW includes the wasm component in every measured request. All wasm
  # component memory/file caches are disabled, so those stapled bytes are used.
  start_as
  run_latency "$TDX_WASM_BODY" "$RESULTS_DIR/eval7_tdx_wasm_latency.json" \
    --warmup 1 "${RETRY_ARGS[@]}"
  stop_as
  save_log "$RESULTS_DIR/logs/eval7_tdx_wasm.log"
)
