#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    cat <<'EOF'
Usage: send-native-snp-attestation.sh [--port <port>] [--evidence <path>] [--output-dir <dir>]

Builds the native SNP attestation request, sends it to /attestation, and saves
the generated artifacts plus the returned token.

Defaults:
  --port       8080
  --evidence   test_data/trustmee-lib/snp_evidence.json
  --output-dir evaluation/trustmee-e2e-perf/results/manual/native-snp-request-<timestamp>
EOF
}

PORT=8080
EVIDENCE_PATH="$DEFAULT_SNP_EVIDENCE_PATH"
OUTPUT_DIR="$DEFAULT_RESULTS_ROOT/manual/native-snp-request-$(timestamp_utc)"

while (($# > 0)); do
    case "$1" in
        --port)
            (($# >= 2)) || die "--port requires a value"
            PORT="$2"
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

EVIDENCE_PATH="$(canonicalize_existing_path "$EVIDENCE_PATH")"
OUTPUT_DIR="$(ensure_directory_absolute "$OUTPUT_DIR")"

ARTIFACTS_DIR="$OUTPUT_DIR/artifacts"
REQUEST_JSON="$(write_native_snp_request_artifacts "$EVIDENCE_PATH" "$ARTIFACTS_DIR")"
RESPONSE_PATH="$OUTPUT_DIR/attest-native-snp-token.txt"
HEADERS_PATH="$OUTPUT_DIR/attest-native-snp-response.headers.txt"

REQUEST_RESULT="$(send_request_with_timing "$PORT" "$REQUEST_JSON" "$RESPONSE_PATH" "$HEADERS_PATH")" || true
read -r HTTP_CODE TIME_MS TOKEN_BYTES <<<"$REQUEST_RESULT"

SUMMARY_PATH="$OUTPUT_DIR/request.summary.txt"
cat >"$SUMMARY_PATH" <<EOF
request: native-snp
port: $PORT
evidence: $EVIDENCE_PATH
request_json: $REQUEST_JSON
response_headers: $HEADERS_PATH
token_path: $RESPONSE_PATH
http_code: $HTTP_CODE
request_time_ms: $TIME_MS
token_bytes: $TOKEN_BYTES
EOF

log_note "request summary: $SUMMARY_PATH"
log_note "request artifacts: $ARTIFACTS_DIR"

if [[ "$HTTP_CODE" != "200" || ! -s "$RESPONSE_PATH" ]]; then
    die "attestation request failed with http_code=$HTTP_CODE, see $SUMMARY_PATH"
fi

log_note "token saved to: $RESPONSE_PATH"
cat "$RESPONSE_PATH"
