#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    cat <<'EOF'
Usage: run-three-cache-requests.sh [--port <port>] [--output-dir <dir>] [--release]

Runs exactly three TrustMee attestation requests and shows cache source transitions:
  1) stapled component source + compiled cache miss
  2) unstapled request in a fresh process (disk HIT + compiled cache miss)
  3) unstapled request in the same process (compiled memory HIT, no CMW disk read)

Defaults:
  --port       19430 (request #1 uses this port, requests #2/#3 use port+1)
  --output-dir evaluation/trustmee-e2e-perf/results/manual/cache-three-requests-<timestamp>
EOF
}

PORT=19430
OUTPUT_DIR="$DEFAULT_RESULTS_ROOT/manual/cache-three-requests-$(timestamp_utc)"
USE_RELEASE=0
COMPONENT_PATH="$DEFAULT_SNP_WASM_COMPONENT_PATH"
EVIDENCE_PATH="$DEFAULT_SNP_EVIDENCE_PATH"

while (($# > 0)); do
    case "$1" in
        --port)
            (($# >= 2)) || die "--port requires a value"
            PORT="$2"
            shift 2
            ;;
        --output-dir)
            (($# >= 2)) || die "--output-dir requires a value"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --release)
            USE_RELEASE=1
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

OUTPUT_DIR="$(ensure_directory_absolute "$OUTPUT_DIR")"
COMPONENT_PATH="$(canonicalize_existing_path "$COMPONENT_PATH")"
EVIDENCE_PATH="$(canonicalize_existing_path "$EVIDENCE_PATH")"

BINARY_PATH="$(build_restful_as "$USE_RELEASE")"
PORT_REQ1="$PORT"
PORT_REQ23="$((PORT + 1))"
WORK_ROOT_REQ1="$OUTPUT_DIR/as-service-state-req1"
WORK_ROOT_REQ23="$OUTPUT_DIR/as-service-state-req23"
REQUEST_ROOT="$OUTPUT_DIR/request-artifacts"
LOG_REQ1="$OUTPUT_DIR/restful-as-req1.log"
LOG_REQ23="$OUTPUT_DIR/restful-as-req23.log"
SUMMARY_PATH="$OUTPUT_DIR/experiment.summary.txt"
TRACE_REQ1="$OUTPUT_DIR/request1.cache-trace.txt"
TRACE_REQ23="$OUTPUT_DIR/request23.cache-trace.txt"

REQUEST_STAPLED="$(write_trustmee_request_artifacts "$COMPONENT_PATH" "$EVIDENCE_PATH" "$REQUEST_ROOT/stapled" 1)"
REQUEST_UNSTAPLED="$(write_trustmee_request_artifacts "$COMPONENT_PATH" "$EVIDENCE_PATH" "$REQUEST_ROOT/unstapled" 0)"

CURRENT_PID=""
cleanup() {
    if [[ -n "$CURRENT_PID" ]]; then
        stop_background_process "$CURRENT_PID"
        CURRENT_PID=""
    fi
}
trap cleanup EXIT INT TERM

export TRUSTMEE_CACHE_TRACE=1

CURRENT_PID="$(start_restful_as_background "$BINARY_PATH" "$PORT_REQ1" "$WORK_ROOT_REQ1" "$LOG_REQ1")"
REQ1_RESULT="$(send_request_with_timing "$PORT_REQ1" "$REQUEST_STAPLED" "$OUTPUT_DIR/request1.token.txt" "$OUTPUT_DIR/request1.headers.txt")"
stop_background_process "$CURRENT_PID"
CURRENT_PID=""

mkdir -p "$WORK_ROOT_REQ23/component-cache/components"
if [[ -d "$WORK_ROOT_REQ1/component-cache/components" ]]; then
    cp -a "$WORK_ROOT_REQ1/component-cache/components/." "$WORK_ROOT_REQ23/component-cache/components/"
fi
mkdir -p "$WORK_ROOT_REQ23/.wasm-verification-component-cache"
if [[ -d "$WORK_ROOT_REQ1/.wasm-verification-component-cache" ]]; then
    cp -a "$WORK_ROOT_REQ1/.wasm-verification-component-cache/." "$WORK_ROOT_REQ23/.wasm-verification-component-cache/"
fi

CURRENT_PID="$(start_restful_as_background "$BINARY_PATH" "$PORT_REQ23" "$WORK_ROOT_REQ23" "$LOG_REQ23")"
REQ2_RESULT="$(send_request_with_timing "$PORT_REQ23" "$REQUEST_UNSTAPLED" "$OUTPUT_DIR/request2.token.txt" "$OUTPUT_DIR/request2.headers.txt")"
REQ3_RESULT="$(send_request_with_timing "$PORT_REQ23" "$REQUEST_UNSTAPLED" "$OUTPUT_DIR/request3.token.txt" "$OUTPUT_DIR/request3.headers.txt")"
stop_background_process "$CURRENT_PID"
CURRENT_PID=""

read -r REQ1_CODE REQ1_MS REQ1_BYTES <<<"$REQ1_RESULT"
read -r REQ2_CODE REQ2_MS REQ2_BYTES <<<"$REQ2_RESULT"
read -r REQ3_CODE REQ3_MS REQ3_BYTES <<<"$REQ3_RESULT"

[[ "$REQ1_CODE" == "200" && "$REQ2_CODE" == "200" && "$REQ3_CODE" == "200" ]] || {
    die "one or more requests failed (codes: $REQ1_CODE/$REQ2_CODE/$REQ3_CODE)"
}

rg -n "CMW component (cache|source)|WVC (load_component|verify_cmw_bytes)" "$LOG_REQ1" >"$TRACE_REQ1" || true
rg -n "CMW component (cache|source)|WVC (load_component|verify_cmw_bytes)" "$LOG_REQ23" >"$TRACE_REQ23" || true

rg -q "CMW component source: STAPLED component" "$TRACE_REQ1" || die "request #1 trace missing stapled component source"
rg -q "WVC verify_cmw_bytes: COMPILED MEMORY MISS" "$TRACE_REQ1" || die "request #1 trace missing compiled cache miss"
rg -q "WVC load_component: MEMORY MISS" "$TRACE_REQ1" || die "request #1 trace missing load_component memory miss"

REQ23_DISK_HIT_COUNT="$(rg -c "CMW component cache: DISK HIT" "$TRACE_REQ23" || printf '0\n')"
[[ "$REQ23_DISK_HIT_COUNT" == "1" ]] || die "request #2/#3 trace expected exactly one DISK HIT, found $REQ23_DISK_HIT_COUNT"
REQ23_COMPILED_MISS_COUNT="$(rg -c "WVC verify_cmw_bytes: COMPILED MEMORY MISS" "$TRACE_REQ23" || printf '0\n')"
[[ "$REQ23_COMPILED_MISS_COUNT" == "1" ]] || die "request #2/#3 trace expected exactly one compiled cache miss, found $REQ23_COMPILED_MISS_COUNT"
REQ23_COMPILED_HIT_COUNT="$(rg -c "WVC verify_cmw_bytes: COMPILED MEMORY HIT" "$TRACE_REQ23" || printf '0\n')"
[[ "$REQ23_COMPILED_HIT_COUNT" == "1" ]] || die "request #2/#3 trace expected exactly one compiled cache hit, found $REQ23_COMPILED_HIT_COUNT"
REQ23_LOAD_MISS_COUNT="$(rg -c "WVC load_component: MEMORY MISS" "$TRACE_REQ23" || printf '0\n')"
[[ "$REQ23_LOAD_MISS_COUNT" == "1" ]] || die "request #2/#3 trace expected exactly one load_component memory miss, found $REQ23_LOAD_MISS_COUNT"
REQ23_LOAD_HIT_COUNT="$(rg -c "WVC load_component: MEMORY HIT" "$TRACE_REQ23" || printf '0\n')"
[[ "$REQ23_LOAD_HIT_COUNT" == "0" ]] || die "request #2/#3 trace expected no load_component memory hit lines, found $REQ23_LOAD_HIT_COUNT"

cat >"$SUMMARY_PATH" <<EOF
experiment: trustmee-cache-three-requests
run_dir: $OUTPUT_DIR
binary: $BINARY_PATH
request_1_port: $PORT_REQ1
request_2_3_port: $PORT_REQ23
request_1_work_root: $WORK_ROOT_REQ1
request_2_3_work_root: $WORK_ROOT_REQ23
component: $COMPONENT_PATH
evidence: $EVIDENCE_PATH
cache_trace_env: TRUSTMEE_CACHE_TRACE=1

request_1_expected: stapled component source + compiled cache miss
request_1_result: $REQ1_CODE $REQ1_MS ms token_bytes=$REQ1_BYTES
request_1_trace: $TRACE_REQ1

request_2_expected: unstapled in fresh process (DISK HIT + COMPILED MEMORY MISS + load_component MEMORY MISS)
request_2_result: $REQ2_CODE $REQ2_MS ms token_bytes=$REQ2_BYTES

request_3_expected: unstapled in warm process (COMPILED MEMORY HIT with no CMW disk read and no load_component call)
request_3_result: $REQ3_CODE $REQ3_MS ms token_bytes=$REQ3_BYTES
request_2_3_trace: $TRACE_REQ23
note: request_2_3 work root is pre-seeded with component-cache + wasmtime compile-cache files from request_1
EOF

log_note "experiment summary: $SUMMARY_PATH"
printf 'request1: %s\nrequest2: %s\nrequest3: %s\n' "$REQ1_RESULT" "$REQ2_RESULT" "$REQ3_RESULT"
printf '\nrequest1 trace:\n'
cat "$TRACE_REQ1"
printf '\nrequest2+3 trace:\n'
cat "$TRACE_REQ23"
