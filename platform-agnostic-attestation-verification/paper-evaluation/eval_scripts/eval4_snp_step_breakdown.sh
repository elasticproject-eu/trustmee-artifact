#!/usr/bin/env bash
# Eval 4: SNP verifier step breakdown (cert_chain, signature, other).
# All three segments are emitted by the native SNP verifier / wasm component
# from the same evaluate run, so the "other" slice is not reconstructed from a
# separate outside verifier span.
#
# Both paths receive the cert chain in their input (native: inline; wasm:
# CMW endorsement) so the collateral fetch path is skipped in both cases.
# Wasm runs in "warm" mode (loaded/pre-instantiated verifier cached; fresh
# instance per request), matching the default used by all evals except the
# explicit hot-cache bars in eval 3.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

SNP_NATIVE_BODY="$TMP_DIR/eval4_snp_native.body.json"
SNP_WASM_BODY="$TMP_DIR/eval4_snp_wasm.body.json"
SNP_WASM_WARMUP_BODY="$TMP_DIR/eval4_snp_wasm.warmup.body.json"

build_snp_native_body "$SNP_NATIVE_BODY" 1
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_BODY" 1 component-id
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_WARMUP_BODY" 1 component

echo "-- SNP native step breakdown --"
(
  export SNP_STEP_TIMING_JSON=1
  export SNP_TIMING_MODE=native
  export SNP_VCEK_DISABLE_CACHE=1
  start_as
  run_latency "$SNP_NATIVE_BODY" "$RESULTS_DIR/eval4_snp_native_e2e.json" --warmup 1
  stop_as
  save_log "$RESULTS_DIR/logs/eval4_snp_native.log"
)

python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
  --log "$RESULTS_DIR/logs/eval4_snp_native.log" \
  --event snp_step_timing \
  --mode native \
  --fields cert_chain_ms signature_ms others_ms total_ms \
  --skip 1 \
  --output "$RESULTS_DIR/eval4_snp_native_step_breakdown.json"

echo "-- SNP wasm step breakdown (warm in-mem cache) --"
(
  export SNP_STEP_TIMING_JSON=1
  export SNP_TIMING_MODE=wasm
  export WVC_EMIT_TIMING=1
  # Warm in-mem wasm cache: cache loaded/pre-instantiated components, but do
  # not reuse instantiated verifier resources.
  start_as
  run_wasm_latency "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval4_snp_wasm_e2e.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval4_snp_wasm.log"
)

python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
  --log "$RESULTS_DIR/logs/eval4_snp_wasm.log" \
  --event snp_step_timing \
  --mode wasm \
  --fields cert_chain_ms signature_ms others_ms total_ms \
  --skip 1 \
  --output "$RESULTS_DIR/eval4_snp_wasm_step_breakdown.json"
