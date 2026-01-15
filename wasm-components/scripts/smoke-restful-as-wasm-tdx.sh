#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PORT="${PORT:-18080}"
WORK_DIR="${WORK_DIR:-/tmp/as-wasm-work}"
CFG_PATH="${CFG_PATH:-/tmp/as-wasm.json}"

COMPONENT_PATH="${COMPONENT_PATH:-target/wasm32-wasip2/release/tdx_verifier_component.wasm}"
QUOTE_PATH="${QUOTE_PATH:-tdx_quote.bin}"
BAD_QUOTE_PATH="${BAD_QUOTE_PATH:-tdx_quote_tampered.bin}"

if [[ ! -f "$COMPONENT_PATH" ]]; then
  echo "component not found: $COMPONENT_PATH" >&2
  echo "hint: build it with: cargo build -p tdx-verifier-component --target wasm32-wasip2 --release" >&2
  exit 2
fi

if [[ ! -f "$QUOTE_PATH" ]]; then
  echo "quote not found: $QUOTE_PATH" >&2
  exit 2
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

python3 - "$CFG_PATH" "$WORK_DIR" "$ROOT_DIR" <<'PY'
import json
import sys

cfg_path = sys.argv[1]
work_dir = sys.argv[2]
root_dir = sys.argv[3]
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
        "enabled": True,
        "allow_unsigned": True,
        "registry_dir": work_dir + "/components",
        "wasi_cache_dir": work_dir + "/wasm-cache",
    },
}
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, separators=(",", ":"))
PY

RUST_LOG="${RUST_LOG:-info}" cargo build -q -p attestation-service --features restful-bin --bin restful-as

RUST_LOG="${RUST_LOG:-info}" target/debug/restful-as --socket "127.0.0.1:${PORT}" -c "$CFG_PATH" \
  >/tmp/restful-as.log 2>&1 &
PID=$!
trap 'kill $PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 200); do
  if curl -sS -o /dev/null "http://127.0.0.1:${PORT}/attestation" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "restful-as exited early; tailing /tmp/restful-as.log" >&2
    tail -n 120 /tmp/restful-as.log >&2 || true
    exit 1
  fi
  sleep 0.25
done

reg_out="$(python3 - "$COMPONENT_PATH" <<'PY' | curl -sS -X POST "http://127.0.0.1:${PORT}/component" -H 'Content-Type: application/json' -d @-
import base64
import json
import sys

p = sys.argv[1]
data = open(p, "rb").read()
component_b64 = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
print(json.dumps({"verifier_component": component_b64}, separators=(",", ":")))
PY
)"

printf '%s' "$reg_out" > /tmp/component-register-response.json

component_id="$(python3 -c 'import json; print(json.load(open("/tmp/component-register-response.json"))["component_id"])')"

evidence_b64url() {
  python3 - "$1" <<'PY'
import base64
import json
import sys

quote = open(sys.argv[1], "rb").read()
evidence = {"quote": base64.b64encode(quote).decode(), "cc_eventlog": None}
payload = json.dumps(evidence, separators=(",", ":")).encode()
print(base64.urlsafe_b64encode(payload).rstrip(b"=").decode())
PY
}

attest() {
  local quote_path="$1"
  local out_path="$2"
  local code_path="$3"

  local evidence
  evidence="$(evidence_b64url "$quote_path")"

  python3 - "$evidence" "$component_id" <<'PY' | curl -sS -o "$out_path" -w '%{http_code}' -X POST "http://127.0.0.1:${PORT}/attestation" -H 'Content-Type: application/json' -d @- >"$code_path" || true
import json
import sys

evidence = sys.argv[1]
component_id = sys.argv[2]
req = {
    "verification_requests": [
        {"tee": "tdx", "evidence": evidence, "verifier_component_id": component_id}
    ],
    "policy_ids": ["default"],
}
print(json.dumps(req, separators=(",", ":")))
PY
}

echo "component_id: $component_id"

attest "$QUOTE_PATH" /tmp/attest-good.out /tmp/attest-good.code
echo "good http: $(cat /tmp/attest-good.code)"
head -c 80 /tmp/attest-good.out; echo

if [[ -f "$BAD_QUOTE_PATH" ]]; then
  attest "$BAD_QUOTE_PATH" /tmp/attest-bad.out /tmp/attest-bad.code
  echo "bad http: $(cat /tmp/attest-bad.code)"
  head -c 140 /tmp/attest-bad.out; echo
else
  echo "skipping tampered-quote test (missing $BAD_QUOTE_PATH)" >&2
fi
