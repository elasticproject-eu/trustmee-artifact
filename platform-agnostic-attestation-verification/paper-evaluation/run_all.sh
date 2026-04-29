#!/usr/bin/env bash
# Entry point: runs the paper evaluations end-to-end and generates figures.
# By default, runs evals 1 through 6. Set NETWORK_OVERHEAD=1 to run only eval 7.
#
# Usage:
#   bash paper-evaluation/run_all.sh [--more-detail]
#   NETWORK_OVERHEAD=1 bash paper-evaluation/run_all.sh
#
# Output:
#   paper-evaluation/results/<timestamp>/
#     system_info.txt
#     eval{1..6}_*.json          # default per-eval metrics
#     eval7_*.json               # NETWORK_OVERHEAD=1 metrics
#     figures/*.pdf              # generated plots for available eval outputs
#     logs/                      # retained AS stderr per eval
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
PAPER_EVAL_ROOT="$REPO_ROOT/paper-evaluation"
BIN_DIR="$PAPER_EVAL_ROOT/bin"
RESULTS_BASE="${RESULTS_DIR_BASE:-$PAPER_EVAL_ROOT/results}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d_%H%M%SZ)}"
RESULTS_DIR="$RESULTS_BASE/$RUN_ID"
TMP_DIR="${TMP_DIR:-$PAPER_EVAL_ROOT/tmp}"
RUNS="${RUNS:-50}"
PORT="${PORT:-18080}"
NETWORK_OVERHEAD="${NETWORK_OVERHEAD:-0}"
MORE_DETAIL="${MORE_DETAIL:-0}"

usage() {
  cat <<'EOF'
Usage: bash paper-evaluation/run_all.sh [--more-detail] [--network-overhead]

Options:
  --more-detail          Also generate detailed/secondary figures.
  --no-more-detail       Generate only the default figure set.
  --network-overhead     Run only eval 7, which measures collateral-fetch network overhead.
  --no-network-overhead  Run the default evals 1 through 6.
  -h, --help             Show this help.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --more-detail)
      MORE_DETAIL=1
      ;;
    --more-detail=*)
      MORE_DETAIL="${1#*=}"
      ;;
    --no-more-detail)
      MORE_DETAIL=0
      ;;
    --network-overhead)
      NETWORK_OVERHEAD=1
      ;;
    --network-overhead=*)
      NETWORK_OVERHEAD="${1#*=}"
      ;;
    --no-network-overhead)
      NETWORK_OVERHEAD=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

case "$NETWORK_OVERHEAD" in
  1|true|TRUE|yes|YES|on|ON)
    NETWORK_OVERHEAD=1
    EVALS=(7)
    ;;
  0|false|FALSE|no|NO|off|OFF|"")
    NETWORK_OVERHEAD=0
    EVALS=(1 2 3 4 5 6)
    ;;
  *)
    echo "ERROR: NETWORK_OVERHEAD must be 0/1, true/false, yes/no, or on/off" >&2
    exit 2
    ;;
esac

case "$MORE_DETAIL" in
  1|true|TRUE|yes|YES|on|ON)
    MORE_DETAIL=1
    ;;
  0|false|FALSE|no|NO|off|OFF|"")
    MORE_DETAIL=0
    ;;
  *)
    echo "ERROR: MORE_DETAIL must be 0/1, true/false, yes/no, or on/off" >&2
    exit 2
    ;;
esac

export REPO_ROOT WORKSPACE_ROOT PAPER_EVAL_ROOT RESULTS_DIR TMP_DIR RUNS PORT NETWORK_OVERHEAD MORE_DETAIL

mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/logs" "$RESULTS_DIR/figures" "$TMP_DIR"

echo "== write system_info =="
bash "$BIN_DIR/write_system_info.sh" "$RESULTS_DIR/system_info.txt"
{
  echo
  echo "run_id: $RUN_ID"
  echo "runs_per_eval: $RUNS"
  echo "network_overhead: $NETWORK_OVERHEAD"
  echo "more_detail: $MORE_DETAIL"
  echo "evals: ${EVALS[*]}"
} >> "$RESULTS_DIR/system_info.txt"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "== build artifacts =="
  bash "$BIN_DIR/build_artifacts.sh"
fi

if [[ "$NETWORK_OVERHEAD" != "1" ]]; then
  # One-off measurement: write request_sizes.json to the results dir.
  # Runs once per invocation (not 50× like the eval scripts) and takes only a
  # few seconds — it just builds the request bodies and stats their sizes.
  echo
  echo "== measure attestation request body sizes =="
  if ! bash "$BIN_DIR/measure_request_sizes.sh"; then
    echo "WARNING: measure_request_sizes.sh failed" >&2
  fi

  # One-off measurement: time wasmtime::component::Component::from_binary for
  # each verifier wasm component, with and without the on-disk compile cache.
  # Writes compile_times.json next to request_sizes.json.
  echo
  echo "== measure wasmtime compile times =="
  if ! bash "$BIN_DIR/measure_compile_times.sh"; then
    echo "WARNING: measure_compile_times.sh failed" >&2
  fi
fi

failures=()
echo
echo "== selected evals: ${EVALS[*]} =="
for i in "${EVALS[@]}"; do
  script="$PAPER_EVAL_ROOT/eval_scripts/eval${i}_"*.sh
  for s in $script; do
    if [[ ! -f "$s" ]]; then
      echo "WARNING: missing eval$i script ($s)" >&2
      continue
    fi
    echo
    echo "===== $(basename "$s") ====="
    # Don't let one failing eval (e.g. network outage) block the others.
    if ! bash "$s"; then
      echo "WARNING: eval$i failed" >&2
      failures+=("eval$i")
    fi
    TMP_DIR="$TMP_DIR" bash "$BIN_DIR/stop_restful_as.sh" >/dev/null 2>&1 || true
  done
done

echo
echo "== generate figures =="
plot_args=(
  --results-dir "$RESULTS_DIR"
  --output-dir "$RESULTS_DIR/figures"
)

if [[ "$MORE_DETAIL" == "1" ]]; then
  plot_args+=(--more-detail)
fi

python3 "$BIN_DIR/plot_figures.py" "${plot_args[@]}"

echo
echo "results: $RESULTS_DIR"
if (( ${#failures[@]} > 0 )); then
  echo "FAILED: ${failures[*]}" >&2
  exit 1
fi
