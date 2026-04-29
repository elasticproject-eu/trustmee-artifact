#!/usr/bin/env bash
# Eval 1: E2E latency WITHOUT collateral fetch.
#
# - SNP native: cert_chain in evidence (skips KDS); SNP_VCEK_DISABLE_CACHE=1
# - SNP wasm:   CMW endorsement carries cert chain; in-memory cache disabled
# - TDX native: measure collateral fetch time separately, subtract from E2E
# - TDX wasm:   CMW endorsement carries TDX collateral; in-memory cache disabled
# - SGX native/wasm follow the TDX pattern with SGX quote/collateral
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../bin/eval_env.sh"

# Pre-build request bodies once.
SNP_NATIVE_BODY="$TMP_DIR/eval1_snp_native.body.json"
SNP_WASM_BODY="$TMP_DIR/eval1_snp_wasm.body.json"
SNP_WASM_WARMUP_BODY="$TMP_DIR/eval1_snp_wasm.warmup.body.json"
TDX_NATIVE_BODY="$TMP_DIR/eval1_tdx_native.body.json"
TDX_WASM_BODY="$TMP_DIR/eval1_tdx_wasm.body.json"
TDX_WASM_WARMUP_BODY="$TMP_DIR/eval1_tdx_wasm.warmup.body.json"
SGX_NATIVE_BODY="$TMP_DIR/eval1_sgx_native.body.json"
SGX_WASM_BODY="$TMP_DIR/eval1_sgx_wasm.body.json"
SGX_WASM_WARMUP_BODY="$TMP_DIR/eval1_sgx_wasm.warmup.body.json"

build_snp_native_body "$SNP_NATIVE_BODY" 1
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_BODY" 1 component-id
build_snp_wasm_body "$SNP_WASM" "$SNP_WASM_WARMUP_BODY" 1 component
build_tdx_native_body "$TDX_NATIVE_BODY"
build_tdx_wasm_body "$TDX_WASM_BODY" 1 component-id
build_tdx_wasm_body "$TDX_WASM_WARMUP_BODY" 1 component
build_sgx_native_body "$SGX_NATIVE_BODY"
build_sgx_wasm_body "$SGX_WASM_BODY" 1 component-id
build_sgx_wasm_body "$SGX_WASM_WARMUP_BODY" 1 component

subtract_collateral_per_request() {
  local tee="$1"
  local mode="$2"
  local attestation_log="$3"
  local as_log="$4"
  local out_path="$5"
  python3 - "$tee" "$mode" "$attestation_log" "$as_log" "$out_path" <<'PY'
import json, statistics, sys

tee, mode, attestation_log, as_log, out_path = sys.argv[1:]

# Per-request E2E times for measured runs only (warmup is not written to
# the result-log by eval_latency.py).
e2e = []
with open(attestation_log, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("event") == "attestation" and rec.get("ok"):
            elapsed = rec.get("elapsed_ms")
            if elapsed is not None:
                e2e.append(float(elapsed))

# Per-request native Intel collateral times. The AS log contains one timing
# event per AS-side request (warmup + measured), in order; skip the first one
# to align with measured E2E samples.
collateral = []
seen = 0
with open(as_log, encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            rec.get("event") == "as_tdx_collateral_timing"
            and rec.get("tee") == tee
            and rec.get("mode") == mode
        ):
            seen += 1
            if seen == 1:
                continue
            ms = rec.get("ms")
            if ms is not None:
                collateral.append(float(ms))

n = min(len(e2e), len(collateral))
if n == 0:
    raise SystemExit(
        f"no paired samples for {tee}/{mode} (e2e={len(e2e)}, collateral={len(collateral)})"
    )
adjusted = [max(e2e[i] - collateral[i], 0.0) for i in range(n)]

result = {
    "runs": n,
    "mean_ms": statistics.fmean(adjusted),
    "std_ms":  statistics.pstdev(adjusted) if n > 1 else 0.0,
    "min_ms":  min(adjusted),
    "max_ms":  max(adjusted),
    "method": "per_request_subtraction",
    "e2e_samples_count": len(e2e),
    "collateral_samples_count": len(collateral),
}
json.dump(result, open(out_path, "w"), indent=2)
print(json.dumps(result, indent=2))
PY
}

echo "-- SNP native --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export SNP_VCEK_DISABLE_CACHE=1
  start_as
  # --warmup absorbs the first-request OPA/RVPS/reqwest init cost that would
  # otherwise appear as a big outlier and inflate std.
  run_latency "$SNP_NATIVE_BODY" "$RESULTS_DIR/eval1_snp_native_latency.json" --warmup 1
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_snp_native.log"
)

echo "-- SNP wasm --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export WASM_TIMING_JSON=1
  start_as
  run_wasm_latency "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval1_snp_wasm_latency.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_snp_wasm.log"
)

echo "-- TDX native (fetch measured) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  start_as
  # --result-log gives us per-request E2E latency in a JSONL file so we can
  # pair each request's E2E sample with its own collateral-fetch event from
  # the AS log and do the subtraction PER REQUEST (not on the means).
  run_latency "$TDX_NATIVE_BODY" "$RESULTS_DIR/eval1_tdx_native_latency_raw.json" \
    --warmup 1 \
    --result-log "$RESULTS_DIR/logs/eval1_tdx_native_attestation.jsonl"
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_tdx_native.log"
)

# Aggregate collateral-fetch time across runs (used only for reporting; the
# real adjusted latency is computed per-request below).
python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
  --log "$RESULTS_DIR/logs/eval1_tdx_native.log" \
  --event as_tdx_collateral_timing \
  --tee Tdx \
  --mode native \
  --skip 1 \
  --output "$RESULTS_DIR/eval1_tdx_native_collateral_time.json"

# Per-request adjustment: pair each request's E2E sample (from the
# attestation result-log) with its corresponding as_tdx_collateral_timing
# event (from the AS log, in order, skipping the warmup), subtract one from
# the other, then compute mean/std across the resulting per-request values.
subtract_collateral_per_request \
  Tdx native \
  "$RESULTS_DIR/logs/eval1_tdx_native_attestation.jsonl" \
  "$RESULTS_DIR/logs/eval1_tdx_native.log" \
  "$RESULTS_DIR/eval1_tdx_native_latency.json"

echo "-- TDX wasm (CMW collateral) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export WASM_TIMING_JSON=1
  start_as
  run_wasm_latency "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval1_tdx_wasm_latency.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_tdx_wasm.log"
)

echo "-- SGX native (fetch measured) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  start_as
  run_latency "$SGX_NATIVE_BODY" "$RESULTS_DIR/eval1_sgx_native_latency_raw.json" \
    --warmup 1 \
    --result-log "$RESULTS_DIR/logs/eval1_sgx_native_attestation.jsonl"
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_sgx_native.log"
)

python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
  --log "$RESULTS_DIR/logs/eval1_sgx_native.log" \
  --event as_tdx_collateral_timing \
  --tee Sgx \
  --mode native \
  --skip 1 \
  --output "$RESULTS_DIR/eval1_sgx_native_collateral_time.json"

subtract_collateral_per_request \
  Sgx native \
  "$RESULTS_DIR/logs/eval1_sgx_native_attestation.jsonl" \
  "$RESULTS_DIR/logs/eval1_sgx_native.log" \
  "$RESULTS_DIR/eval1_sgx_native_latency.json"

SGX_DCAP_CACHE="$TMP_DIR/eval1_sgx_dcap_qvl_cache"
rm -rf "$SGX_DCAP_CACHE"
mkdir -p "$SGX_DCAP_CACHE"

echo "-- SGX native via dcap-qvl --"
if (
  export AS_VERIFICATION_TIMING_JSON=1
  export SGX_NATIVE_USE_DCAP_QVL=1
  export DCAP_QVL_CACHE_DIR="$SGX_DCAP_CACHE"
  start_as
  set +e
  run_latency "$SGX_NATIVE_BODY" "$RESULTS_DIR/eval1_sgx_native_dcap_qvl_e2e.json" --warmup 2
  rc=$?
  set -e
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_sgx_native_dcap_qvl.log"
  exit "$rc"
); then
  python3 "$PAPER_EVAL_ROOT/bin/parse_timings.py" \
    --log "$RESULTS_DIR/logs/eval1_sgx_native_dcap_qvl.log" \
    --event as_verifier_timing \
    --tee Sgx \
    --mode native \
    --skip 2 \
    --output "$RESULTS_DIR/eval1_sgx_native_verifier_dcap_qvl.json"
else
  echo "WARNING: SGX native via dcap-qvl failed; continuing" >&2
fi

echo "-- SGX wasm (CMW collateral) --"
if (
  export AS_VERIFICATION_TIMING_JSON=1
  export TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1
  export WASM_TIMING_JSON=1
  start_as
  set +e
  run_wasm_latency "$SGX_WASM_BODY" "$SGX_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval1_sgx_wasm_latency.json"
  rc=$?
  set -e
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_sgx_wasm.log"
  exit "$rc"
); then
  :
else
  echo "WARNING: SGX wasm failed; continuing" >&2
fi

# A second wasm pass with the warm in-memory component cache ENABLED. The CMW
# still carries the collateral (no fetch) and the native bars stay the same
# as above, so plot_figures.py reuses the same eval1_*_native_latency.json
# files when generating the cache-on variant of fig 1.
echo "-- SNP wasm (CMW collateral, warm in-mem cache ON) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export WASM_TIMING_JSON=1
  start_as
  run_wasm_latency "$SNP_WASM_BODY" "$SNP_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval1_snp_wasm_latency_hot.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_snp_wasm_hot.log"
)

echo "-- TDX wasm (CMW collateral, warm in-mem cache ON) --"
(
  export AS_VERIFICATION_TIMING_JSON=1
  export WASM_TIMING_JSON=1
  start_as
  run_wasm_latency "$TDX_WASM_BODY" "$TDX_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval1_tdx_wasm_latency_hot.json"
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_tdx_wasm_hot.log"
)

echo "-- SGX wasm (CMW collateral, warm in-mem cache ON) --"
if (
  export AS_VERIFICATION_TIMING_JSON=1
  export WASM_TIMING_JSON=1
  start_as
  set +e
  run_wasm_latency "$SGX_WASM_BODY" "$SGX_WASM_WARMUP_BODY" \
    "$RESULTS_DIR/eval1_sgx_wasm_latency_hot.json"
  rc=$?
  set -e
  stop_as
  save_log "$RESULTS_DIR/logs/eval1_sgx_wasm_hot.log"
  exit "$rc"
); then
  :
else
  echo "WARNING: SGX wasm warm-cache pass failed; continuing" >&2
fi
