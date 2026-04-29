#!/usr/bin/env bash
# Eval 5: SNP wasm-crypto vs host-crypto when the in-memory cache is enabled.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

SNP_WASM_BODY="$TMP_DIR/eval5_snp_wasm.body.json"
SNP_WASM_WARMUP_BODY="$TMP_DIR/eval5_snp_wasm.warmup.body.json"
SNP_HOST_BODY="$TMP_DIR/eval5_snp_host.body.json"
SNP_HOST_WARMUP_BODY="$TMP_DIR/eval5_snp_host.warmup.body.json"

build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_BODY" 1 component-id
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_WARMUP_BODY" 1 component
build_snp_wasm_body "$SNP_WASM_HOST" "$SNP_HOST_BODY" 1 component-id
build_snp_wasm_body "$SNP_WASM_HOST" "$SNP_HOST_WARMUP_BODY" 1 component

echo "-- SNP wasm crypto (in-mem cache on) --"
(
  start_as
  run_wasm_latency "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval5_snp_wasm_crypto_latency.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval5_snp_wasm_crypto.log"
)

echo "-- SNP host crypto (in-mem cache on) --"
(
  start_as
  run_wasm_latency "$SNP_HOST_BODY" "$SNP_HOST_WARMUP_BODY" \
    "$RESULTS_DIR/eval5_snp_host_crypto_latency.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval5_snp_host_crypto.log"
)
