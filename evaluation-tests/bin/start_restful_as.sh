#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
if [[ -z "$MODE" ]]; then
  echo "usage: $0 <native|wasm>" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${PORT:-18080}"
WORK_DIR="${WORK_DIR:-/tmp/as-eval-${MODE}}"
TMP_DIR="${TMP_DIR:-$ROOT_DIR/evaluation-tests/tmp}"
CFG_PATH="${CFG_PATH:-$TMP_DIR/as-${MODE}.json}"
LOG_PATH="${LOG_PATH:-$TMP_DIR/restful-as-${MODE}.log}"
PID_PATH="${PID_PATH:-$TMP_DIR/restful-as-${MODE}.pid}"
QCNL_CONFIG_PATH="${QCNL_CONFIG_PATH:-$TMP_DIR/sgx_default_qcnl.conf}"
RESTFUL_BIN="${RESTFUL_BIN:-$ROOT_DIR/target/release/restful-as}"

mkdir -p "$TMP_DIR"
rm -f "$LOG_PATH" "$PID_PATH"
if [[ ! -f "$QCNL_CONFIG_PATH" ]]; then
  cp "$ROOT_DIR/attestation-service/docs/sgx_default_qcnl.conf" "$QCNL_CONFIG_PATH"
fi

if [[ ! -x "$RESTFUL_BIN" ]]; then
  echo "restful-as not found: $RESTFUL_BIN" >&2
  echo "build it with: evaluation-tests/bin/build_artifacts.sh" >&2
  exit 2
fi

python3 - "$CFG_PATH" "$WORK_DIR" "$ROOT_DIR" "$MODE" <<'PY'
import json
import os
import sys

cfg_path = sys.argv[1]
work_dir = sys.argv[2]
root_dir = sys.argv[3]
mode = sys.argv[4]
wasm_enabled = mode == "wasm"
trusted_keys_env = os.environ.get("WASM_TRUSTED_PUBLIC_KEYS", "")
trusted_keys = [p for p in trusted_keys_env.split(os.pathsep) if p]
allow_unsigned_env = os.environ.get("WASM_ALLOW_UNSIGNED")
if allow_unsigned_env is None:
    allow_unsigned = not bool(trusted_keys)
else:
    allow_unsigned = allow_unsigned_env.strip().lower() in ("1", "true", "yes", "y")
cfg = {
    "work_dir": work_dir,
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {"type": "LocalFs", "file_path": work_dir + "/reference-values"},
    },
    "attestation_token_broker": {
        "policy_dir": root_dir + "/attestation-service/tests/coco-as/policy",
    },
    "wasm_verifier": {
        "enabled": wasm_enabled,
        "allow_unsigned": allow_unsigned,
        "trusted_public_keys": trusted_keys,
        "registry_dir": work_dir + "/components",
        "wasi_cache_dir": work_dir + "/wasm-cache",
    },
}
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, separators=(",", ":"))
PY

QCNL_CONF_PATH="$QCNL_CONFIG_PATH" \
SGX_QCNL_CONFIG_FILE="$QCNL_CONFIG_PATH" \
RUST_LOG="${RUST_LOG:-info}" "$RESTFUL_BIN" --socket "127.0.0.1:${PORT}" -c "$CFG_PATH" \
  >"$LOG_PATH" 2>&1 &
PID=$!
echo "$PID" > "$PID_PATH"

for _ in $(seq 1 200); do
  if curl -sS -o /dev/null "http://127.0.0.1:${PORT}/attestation" 2>/dev/null; then
    exit 0
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "restful-as exited early; tailing $LOG_PATH" >&2
    tail -n 120 "$LOG_PATH" >&2 || true
    exit 1
  fi
  sleep 0.25
done

echo "restful-as did not become ready in time" >&2
exit 1
