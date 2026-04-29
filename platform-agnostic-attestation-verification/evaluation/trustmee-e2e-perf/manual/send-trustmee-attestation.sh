#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    cat <<'EOF'
Usage: send-trustmee-attestation.sh [--port <port>] [--component <path>] [--evidence <path>] [--output-dir <dir>] [--unstapled]

Builds the TrustMee EAT + CMW request, sends it to /attestation, and saves
the generated artifacts plus the returned token.

Defaults:
  --port       8080
  --component  test_data/trustmee-lib/snp_verifier_component.wasm
  --evidence   test_data/trustmee-lib/snp_evidence.json
  --output-dir evaluation/trustmee-e2e-perf/results/manual/request-<timestamp>
  --unstapled  omit CMW `verifier` endorsement and rely on component cache / OCI
EOF
}

PORT=8080
COMPONENT_PATH="$DEFAULT_SNP_WASM_COMPONENT_PATH"
EVIDENCE_PATH="$DEFAULT_SNP_EVIDENCE_PATH"
OUTPUT_DIR="$DEFAULT_RESULTS_ROOT/manual/request-$(timestamp_utc)"
INCLUDE_STAPLED_COMPONENT=1

while (($# > 0)); do
    case "$1" in
        --port)
            (($# >= 2)) || die "--port requires a value"
            PORT="$2"
            shift 2
            ;;
        --component)
            (($# >= 2)) || die "--component requires a value"
            COMPONENT_PATH="$2"
            shift 2
            ;;
        --evidence)
            (($# >= 2)) || die "--evidence requires a value"
            EVIDENCE_PATH="$2"
            shift 2
            ;;
        --output-dir)
            (($# >= 2)) || die "--output-dir requires a value"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --unstapled)
            INCLUDE_STAPLED_COMPONENT=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

ensure_common_prereqs

COMPONENT_PATH="$(canonicalize_existing_path "$COMPONENT_PATH")"
EVIDENCE_PATH="$(canonicalize_existing_path "$EVIDENCE_PATH")"
OUTPUT_DIR="$(ensure_directory_absolute "$OUTPUT_DIR")"

ARTIFACTS_DIR="$OUTPUT_DIR/artifacts"
REQUEST_JSON="$(write_trustmee_request_artifacts "$COMPONENT_PATH" "$EVIDENCE_PATH" "$ARTIFACTS_DIR" "$INCLUDE_STAPLED_COMPONENT")"
RESPONSE_PATH="$OUTPUT_DIR/attest-trustmee-token.txt"
HEADERS_PATH="$OUTPUT_DIR/attest-trustmee-response.headers.txt"

REQUEST_RESULT="$(send_request_with_timing "$PORT" "$REQUEST_JSON" "$RESPONSE_PATH" "$HEADERS_PATH")" || true
read -r HTTP_CODE TIME_MS TOKEN_BYTES <<<"$REQUEST_RESULT"

SUMMARY_PATH="$OUTPUT_DIR/request.summary.txt"
cat >"$SUMMARY_PATH" <<EOF
request: wasm-snp
port: $PORT
component: $COMPONENT_PATH
evidence: $EVIDENCE_PATH
request_json: $REQUEST_JSON
response_headers: $HEADERS_PATH
token_path: $RESPONSE_PATH
http_code: $HTTP_CODE
request_time_ms: $TIME_MS
token_bytes: $TOKEN_BYTES
stapled_component: $INCLUDE_STAPLED_COMPONENT
EOF

log_note "request summary: $SUMMARY_PATH"
log_note "request artifacts: $ARTIFACTS_DIR"

if [[ "$HTTP_CODE" != "200" || ! -s "$RESPONSE_PATH" ]]; then
    die "attestation request failed with http_code=$HTTP_CODE, see $SUMMARY_PATH"
fi

log_note "token saved to: $RESPONSE_PATH"
cat "$RESPONSE_PATH"
