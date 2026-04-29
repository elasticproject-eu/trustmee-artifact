#!/usr/bin/env bash
# Time `wasmtime::component::Component::from_binary` for each verifier wasm
# component, with and without the on-disk compilation cache. Writes a JSON
# summary to $RESULTS_DIR/compile_times.json so the result is reproducible
# alongside the rest of the eval artifacts.
#
# Run order assumption: invoked from run_all.sh AFTER build_artifacts.sh so
# the helper binary and the wasm components both exist.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/eval_env.sh"

OUT_JSON="${1:-$RESULTS_DIR/compile_times.json}"
RUNS="${COMPILE_BENCH_RUNS:-5}"
BENCH_TMP="$TMP_DIR/wasmtime_compile_bench"
rm -rf "$BENCH_TMP"
mkdir -p "$BENCH_TMP"

echo "== timing wasmtime Component::from_binary (runs=$RUNS per regime) =="

components=(
  "snp_verifier=$SNP_WASM"
  "snp_verifier_host_crypto=$SNP_WASM_HOST"
  "tdx_verifier=$TDX_WASM"
)

cmd=("$WASMTIME_COMPILE_BENCH_CLI" --runs "$RUNS" --bench-dir "$BENCH_TMP" --output "$OUT_JSON")
for spec in "${components[@]}"; do
  cmd+=(--component "$spec")
done

"${cmd[@]}"
