#!/usr/bin/env bash
# Eval 2: breakdown of wasm load/instantiate vs verify for SNP and TDX.
# In-memory cache disabled so every request re-loads; wasmtime disk cache still
# applies. WASM_TIMING_JSON emits wvc_load_timing / wvc_instantiate_timing /
# wvc_verify_timing / wvc_total_timing events.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

SNP_WASM_BODY="$TMP_DIR/eval2_snp_wasm.body.json"
SNP_WASM_WARMUP_BODY="$TMP_DIR/eval2_snp_wasm.warmup.body.json"
TDX_WASM_BODY="$TMP_DIR/eval2_tdx_wasm.body.json"
TDX_WASM_WARMUP_BODY="$TMP_DIR/eval2_tdx_wasm.warmup.body.json"

build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_BODY" 1 component-id
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_WARMUP_BODY" 1 component
build_tdx_wasm_body "$TDX_WASM_BODY" 1 component-id
build_tdx_wasm_body "$TDX_WASM_WARMUP_BODY" 1 component

echo "-- SNP wasm (load/verify breakdown) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export WASM_TIMING_JSON=1
  start_as
  run_wasm_latency "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval2_snp_wasm_e2e.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval2_snp_wasm.log"
)

echo "-- TDX wasm (load/verify breakdown) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export WASM_TIMING_JSON=1
  export WVC_EMIT_TIMING=1
  start_as
  run_wasm_latency "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval2_tdx_wasm_e2e.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval2_tdx_wasm.log"
)

# Extract the four timings per platform. Skip the warmup-driven first events.
merge_breakdown() {
  local log="$1" out="$2" tee_cap="$3"
  local tmp="$TMP_DIR/$(basename "${out%.json}")"
  for ev in wvc_load_timing wvc_instantiate_timing wvc_verify_timing wvc_total_timing; do
    python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
      --log "$log" --event "$ev" --skip 1 \
      --output "${tmp}_${ev}.json" >/dev/null
  done
  # Also collect the full AS-verifier span so the caller can compare the
  # sum of host-side wasm sub-phases to the enclosing verifier.evaluate()
  # time (which additionally includes CMW parse, thread spawn/join and
  # other AS-side bookkeeping).
  parse_as_verifier_timing_with_fallback \
    "$log" wasm 1 "${tmp}_as_verifier_timing.json" "$tee_cap" Sample
  python3 - <<PY
import json
load = json.load(open("${tmp}_wvc_load_timing.json"))["ms"]
inst = json.load(open("${tmp}_wvc_instantiate_timing.json"))["ms"]
verify = json.load(open("${tmp}_wvc_verify_timing.json"))["ms"]
total = json.load(open("${tmp}_wvc_total_timing.json"))["ms"]
asv = json.load(open("${tmp}_as_verifier_timing.json"))["ms"]
other_mean = max(asv["mean"] - (load["mean"] + inst["mean"] + verify["mean"]), 0.0)
json.dump({
  "load":        load,
  "instantiate": inst,
  "verify":      verify,
  "total":       total,
  "as_verifier": asv,
  "other_mean":  other_mean,
}, open("$out", "w"), indent=2)
print(open("$out").read())
PY
}

merge_breakdown "$RESULTS_DIR/logs/eval2_snp_wasm.log" "$RESULTS_DIR/eval2_snp_wasm_breakdown.json" "Snp"
merge_breakdown "$RESULTS_DIR/logs/eval2_tdx_wasm.log" "$RESULTS_DIR/eval2_tdx_wasm_breakdown.json" "Tdx"
