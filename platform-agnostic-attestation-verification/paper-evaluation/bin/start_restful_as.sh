#!/usr/bin/env bash
# Launch restful-as with a generated config file and wait for readiness.
# Environment (with defaults):
#   PORT                 18080
#   WORK_DIR             /tmp/paper-eval-as
#   TMP_DIR              $PAPER_EVAL_ROOT/tmp
#   CFG_PATH             $TMP_DIR/as.json
#   LOG_PATH             $TMP_DIR/restful-as.log
#   PID_PATH             $TMP_DIR/restful-as.pid
#   RESTFUL_BIN          $REPO_ROOT/target/release/restful-as
#   QCNL_CONFIG_PATH     $TMP_DIR/sgx_default_qcnl.conf
#   RUST_LOG             info
# All paper-eval hooks (AS_VERIFICATION_TIMING_JSON, SNP_STEP_TIMING_JSON,
# SNP_TIMING_MODE, SNP_VCEK_DISABLE_CACHE, TDX_NATIVE_USE_DCAP_QVL,
# DCAP_QVL_DISABLE_CACHE, DCAP_QVL_CACHE_DIR, TRUSTMEE_WASM_DISABLE_INMEM_CACHE,
# TRUSTMEE_WASM_INMEM_CACHE_MODE, TRUSTMEE_WASM_DISABLE_COMPONENT_FILE_CACHE,
# TRUSTMEE_WASM_DISABLE_WASMTIME_CACHE, WASM_TIMING_JSON, WVC_EMIT_TIMING) are
# passed through by the calling script.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PAPER_EVAL_ROOT="$REPO_ROOT/paper-evaluation"

PORT="${PORT:-18080}"
WORK_DIR="${WORK_DIR:-/tmp/paper-eval-as}"
TMP_DIR="${TMP_DIR:-$PAPER_EVAL_ROOT/tmp}"
CFG_PATH="${CFG_PATH:-$TMP_DIR/as.json}"
LOG_PATH="${LOG_PATH:-$TMP_DIR/restful-as.log}"
PID_PATH="${PID_PATH:-$TMP_DIR/restful-as.pid}"
QCNL_CONFIG_PATH="${QCNL_CONFIG_PATH:-$TMP_DIR/sgx_default_qcnl.conf}"
RESTFUL_BIN="${RESTFUL_BIN:-$REPO_ROOT/target/release/restful-as}"

mkdir -p "$TMP_DIR" "$WORK_DIR"
rm -f "$LOG_PATH" "$PID_PATH"

if curl -sS -o /dev/null "http://127.0.0.1:${PORT}/attestation" 2>/dev/null; then
  echo "port ${PORT} already has a service before starting restful-as" >&2
  echo "stop the stale service or use a different PORT" >&2
  exit 1
fi

if [[ ! -f "$QCNL_CONFIG_PATH" ]]; then
  # Minimal QCNL config — accept self-signed PCCS and prefer Intel PCS.
  cat >"$QCNL_CONFIG_PATH" <<JSON
{
  "pccs_url": "${PCCS_URL:-https://api.trustedservices.intel.com/sgx/certification/v4/}",
  "use_secure_cert": false,
  "collateral_service": "${COLLATERAL_URL:-https://api.trustedservices.intel.com/sgx/certification/v4/}"
}
JSON
fi

if [[ ! -x "$RESTFUL_BIN" ]]; then
  echo "restful-as not found: $RESTFUL_BIN" >&2
  echo "build it with: paper-evaluation/bin/build_artifacts.sh" >&2
  exit 2
fi

python3 - "$CFG_PATH" "$WORK_DIR" <<'PY'
import json, os, sys
cfg_path, work_dir = sys.argv[1], sys.argv[2]
policy_dir = work_dir + "/token/policies"
os.makedirs(policy_dir, exist_ok=True)
cfg = {
    "work_dir": work_dir,
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {"type": "LocalFs", "file_path": work_dir + "/reference-values"},
    },
    "attestation_token_broker": {
        "policy_dir": policy_dir,
    },
    "wasm_component_registry": {
        "component_cache_base_dir": work_dir + "/components",
    },
}
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, separators=(",", ":"))
PY

QCNL_CONF_PATH="$QCNL_CONFIG_PATH" \
SGX_QCNL_CONFIG_FILE="$QCNL_CONFIG_PATH" \
RUST_LOG="${RUST_LOG:-info}" \
  "$RESTFUL_BIN" --socket "127.0.0.1:${PORT}" -c "$CFG_PATH" \
    >"$LOG_PATH" 2>&1 &
PID=$!
echo "$PID" > "$PID_PATH"
READY_LINE="starting HTTP server at http://127.0.0.1:${PORT}"

for _ in $(seq 1 200); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "restful-as exited early; tailing $LOG_PATH" >&2
    tail -n 120 "$LOG_PATH" >&2 || true
    exit 1
  fi
  if grep -Fq "$READY_LINE" "$LOG_PATH" 2>/dev/null; then
    if curl -sS -o /dev/null "http://127.0.0.1:${PORT}/attestation" 2>/dev/null; then
      if kill -0 "$PID" 2>/dev/null; then
        exit 0
      fi
    fi
  fi
  sleep 0.25
done

echo "restful-as did not become ready in time" >&2
tail -n 120 "$LOG_PATH" >&2 || true
exit 1
