#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
BINARY_PATH="$ROOT_DIR/target/debug/wasm-verification-component"

UNSIGNED_COMPONENT="$ROOT_DIR/test_data/snp_verifier_component.wasm"
SIGNED_COMPONENT="$ROOT_DIR/test_data/signature-demo/snp_verifier_component.signed.wasm"
EVIDENCE_PATH="$ROOT_DIR/test_data/snp_evidence.json"
TRUST_STORE_PATH="$ROOT_DIR/test_data/signature-demo/snp_verifier_component.trust-store.json"

echo "Building wasm-verification-component CLI..."
cargo build --manifest-path "$MANIFEST_PATH" --bin wasm-verification-component >/dev/null

if [[ ! -f "$UNSIGNED_COMPONENT" ]]; then
  echo "Missing unsigned component: $UNSIGNED_COMPONENT" >&2
  exit 1
fi
if [[ ! -f "$SIGNED_COMPONENT" ]]; then
  echo "Missing signed component: $SIGNED_COMPONENT" >&2
  exit 1
fi
if [[ ! -f "$EVIDENCE_PATH" ]]; then
  echo "Missing SNP evidence: $EVIDENCE_PATH" >&2
  exit 1
fi
if [[ ! -f "$TRUST_STORE_PATH" ]]; then
  echo "Missing trust store: $TRUST_STORE_PATH" >&2
  exit 1
fi

run_success_case() {
  local label="$1"
  shift
  local cache_dir
  cache_dir="$(mktemp -d)"
  echo
  echo "== $label =="
  local output
  output="$("$BINARY_PATH" "$@" --cache-dir "$cache_dir" --compact)"
  echo "$output"
  echo "$output" | grep -q '"tee_type":"snp"'
}

echo
echo "Testing unsigned SNP verifier component without a trust store..."
run_success_case \
  "Unsigned component without trust store" \
  --component "$UNSIGNED_COMPONENT" \
  --evidence "$EVIDENCE_PATH"

echo
echo "Testing signed SNP verifier component with the sample trust store..."
run_success_case \
  "Signed component with trust store" \
  --component "$SIGNED_COMPONENT" \
  --evidence "$EVIDENCE_PATH" \
  --component-trust-store "$TRUST_STORE_PATH"

echo
echo "Testing that signed SNP verifier component is rejected with an expired trust store..."
expired_trust_store="$(mktemp)"
sed 's/2035-01-01T00:00:00Z/1970-01-01T00:00:01Z/' "$TRUST_STORE_PATH" >"$expired_trust_store"
negative_cache_dir="$(mktemp -d)"
if "$BINARY_PATH" \
  --component "$SIGNED_COMPONENT" \
  --evidence "$EVIDENCE_PATH" \
  --component-trust-store "$expired_trust_store" \
  --cache-dir "$negative_cache_dir" \
  --compact
then
  echo "Signed component unexpectedly succeeded with an expired trust store" >&2
  exit 1
else
  echo "Signed component was correctly rejected with an expired trust store."
fi

echo
echo "Testing signed SNP verifier component without a trust store in direct compatibility mode..."
run_success_case \
  "Signed component without trust store (legacy direct mode)" \
  --component "$SIGNED_COMPONENT" \
  --evidence "$EVIDENCE_PATH"

echo
echo "Manual SNP signature tests completed successfully."
