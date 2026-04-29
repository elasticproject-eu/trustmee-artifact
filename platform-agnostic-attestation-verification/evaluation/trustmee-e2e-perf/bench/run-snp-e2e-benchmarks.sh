#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    cat <<'EOF'
Usage: run-snp-e2e-benchmarks.sh [--iterations <n>] [--warmup <n>] [--results-dir <dir>] [--port-base <port>] [--release]

Runs these scenarios:
  - native_snp_warm_process
  - native_snp_fresh_process
  - wasm_snp_disk_cache
  - wasm_snp_memory_cache
  - wasm_snp_host_crypto_memory_cache
EOF
}

ITERATIONS=20
WARMUP=3
RESULTS_DIR="$DEFAULT_RESULTS_ROOT"
PORT_BASE=19080
USE_RELEASE=0

while (($# > 0)); do
    case "$1" in
        --iterations)
            (($# >= 2)) || die "--iterations requires a value"
            ITERATIONS="$2"
            shift 2
            ;;
        --warmup)
            (($# >= 2)) || die "--warmup requires a value"
            WARMUP="$2"
            shift 2
            ;;
        --results-dir)
            (($# >= 2)) || die "--results-dir requires a value"
            RESULTS_DIR="$2"
            shift 2
            ;;
        --port-base)
            (($# >= 2)) || die "--port-base requires a value"
            PORT_BASE="$2"
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
[[ "$ITERATIONS" =~ ^[0-9]+$ ]] || die "--iterations must be a non-negative integer"
[[ "$WARMUP" =~ ^[0-9]+$ ]] || die "--warmup must be a non-negative integer"
(( ITERATIONS > 0 )) || die "--iterations must be greater than zero"
[[ "$PORT_BASE" =~ ^[0-9]+$ ]] || die "--port-base must be a non-negative integer"
CURRENT_AS_PID=""
OVERALL_FAILURES=0
FRESH_PROCESS_SAMPLE_COUNT=$((1 + WARMUP + ITERATIONS))
TOTAL_PORT_SPAN=$((3 + (2 * FRESH_PROCESS_SAMPLE_COUNT)))

cleanup() {
    if [[ -n "$CURRENT_AS_PID" ]]; then
        stop_background_process "$CURRENT_AS_PID"
        CURRENT_AS_PID=""
    fi
}

trap cleanup EXIT INT TERM

port_is_occupied() {
    local port="$1"
    timeout 0.2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" >/dev/null 2>&1
}

find_available_port_base() {
    local requested_base="$1"
    local port_span="$2"
    local candidate="$requested_base"
    local attempts=256

    while (( attempts > 0 )); do
        local port
        local busy=0
        for ((port = candidate; port < candidate + port_span; port++)); do
            if port_is_occupied "$port"; then
                busy=1
                break
            fi
        done

        if (( busy == 0 )); then
            printf '%s\n' "$candidate"
            return 0
        fi

        candidate=$((port + 1))
        attempts=$((attempts - 1))
    done

    die "could not find $port_span consecutive free ports starting at or above $requested_base"
}

REQUESTED_PORT_BASE="$PORT_BASE"
PORT_BASE="$(find_available_port_base "$PORT_BASE" "$TOTAL_PORT_SPAN")"
if [[ "$PORT_BASE" != "$REQUESTED_PORT_BASE" ]]; then
    log_note "requested port base $REQUESTED_PORT_BASE is busy; using $PORT_BASE instead"
fi

NATIVE_WARM_PORT="$PORT_BASE"
NATIVE_FRESH_PORT_BASE=$((NATIVE_WARM_PORT + 1))
WASM_DISK_PORT_BASE=$((NATIVE_FRESH_PORT_BASE + FRESH_PROCESS_SAMPLE_COUNT))
WASM_MEMORY_PORT=$((WASM_DISK_PORT_BASE + FRESH_PROCESS_SAMPLE_COUNT))
WASM_HOST_CRYPTO_MEMORY_PORT=$((WASM_MEMORY_PORT + 1))

RESULTS_DIR="$(ensure_directory_absolute "$RESULTS_DIR")"
RUN_ROOT="$(ensure_directory_absolute "$RESULTS_DIR/$(timestamp_utc)")"
COMPARISON_SUMMARY="$RUN_ROOT/comparison.summary.txt"
BINARY_PATH="$(build_restful_as "$USE_RELEASE")"

record_csv_header() {
    local csv_path="$1"
    printf 'phase,iteration,http_code,time_ms,token_bytes,response_file\n' >"$csv_path"
}

record_sample_row() {
    local csv_path="$1"
    local phase="$2"
    local iteration="$3"
    local http_code="$4"
    local time_ms="$5"
    local token_bytes="$6"
    local response_file="$7"
    printf '%s,%s,%s,%s,%s,%s\n' \
        "$phase" "$iteration" "$http_code" "$time_ms" "$token_bytes" "$response_file" >>"$csv_path"
}

run_request_sample() {
    local port="$1"
    local request_json="$2"
    local responses_dir="$3"
    local csv_path="$4"
    local phase="$5"
    local iteration="$6"

    local label
    label="$(printf '%s-%03d' "$phase" "$iteration")"
    local response_path="$responses_dir/$label.token.txt"
    local headers_path="$responses_dir/$label.headers.txt"
    local result

    if ! result="$(send_request_with_timing "$port" "$request_json" "$response_path" "$headers_path")"; then
        result="000 0.000 0"
    fi

    local http_code time_ms token_bytes
    read -r http_code time_ms token_bytes <<<"$result"
    record_sample_row "$csv_path" "$phase" "$iteration" "$http_code" "$time_ms" "$token_bytes" "$(basename "$response_path")"

    if [[ "$http_code" != "200" || ! -s "$response_path" ]]; then
        return 1
    fi
    return 0
}

write_scenario_summary() {
    local scenario="$1"
    local scenario_dir="$2"
    local csv_path="$3"
    local component_label="$4"
    local evidence_path="$5"
    local note_text="$6"
    local config_path="$7"
    local prime_request_path="$8"
    local steady_request_path="$9"

    local summary_path="$scenario_dir/$scenario.summary.txt"
    local prime_ms avg_ms min_ms max_ms sample_count success_count failure_count

    prime_ms="$(phase_time_from_csv "$csv_path" "prime" || printf 'n/a')"
    read -r avg_ms min_ms max_ms sample_count <<<"$(measurement_stats_from_csv "$csv_path")"
    read -r success_count failure_count <<<"$(success_failure_counts_from_csv "$csv_path")"

    cat >"$summary_path" <<EOF
scenario: $scenario
component: $component_label
evidence: $evidence_path
iterations: $ITERATIONS
warmup: $WARMUP
prime_request_ms: $prime_ms
request_avg_ms: $avg_ms
request_min_ms: $min_ms
request_max_ms: $max_ms
measured_sample_count: $sample_count
success_count: $success_count
failure_count: $failure_count
config_path: $config_path
prime_request_path: $prime_request_path
steady_state_request_path: $steady_request_path
samples_csv: $csv_path
log_file: $scenario_dir/restful-as.log
note: $note_text
EOF
}

collect_comparison_summary() {
    local summary_path="$1"
    local scenario avg min max prime success failure note

    scenario="$(awk -F': ' '$1=="scenario" {print $2}' "$summary_path")"
    avg="$(awk -F': ' '$1=="request_avg_ms" {print $2}' "$summary_path")"
    min="$(awk -F': ' '$1=="request_min_ms" {print $2}' "$summary_path")"
    max="$(awk -F': ' '$1=="request_max_ms" {print $2}' "$summary_path")"
    prime="$(awk -F': ' '$1=="prime_request_ms" {print $2}' "$summary_path")"
    success="$(awk -F': ' '$1=="success_count" {print $2}' "$summary_path")"
    failure="$(awk -F': ' '$1=="failure_count" {print $2}' "$summary_path")"
    note="$(awk -F': ' '$1=="note" {print $2}' "$summary_path")"

    printf '%-34s avg=%8s ms  min=%8s ms  max=%8s ms  prime=%8s ms  success=%3s  failure=%3s\n' \
        "$scenario" "$avg" "$min" "$max" "$prime" "$success" "$failure" >>"$COMPARISON_SUMMARY"
    printf 'note: %s\n' "$note" >>"$COMPARISON_SUMMARY"
}

run_warm_process_scenario() {
    local scenario="$1"
    local port="$2"
    local request_kind="$3"
    local request_input="$4"
    local component_label="$5"
    local evidence_path="$6"
    local note_text="$7"

    local scenario_dir
    scenario_dir="$(ensure_directory_absolute "$RUN_ROOT/$scenario")"
    local responses_dir="$scenario_dir/responses"
    local work_root="$scenario_dir/service-state"
    local request_dir="$scenario_dir/request-artifacts"
    local csv_path="$scenario_dir/$scenario.samples.csv"
    local log_file="$scenario_dir/restful-as.log"
    mkdir -p "$responses_dir"
    record_csv_header "$csv_path"

    local request_json_prime
    local request_json_steady
    case "$request_kind" in
        native)
            request_json_prime="$(write_native_snp_request_artifacts "$evidence_path" "$request_dir")"
            request_json_steady="$request_json_prime"
            ;;
        trustmee)
            request_json_prime="$(write_trustmee_request_artifacts "$request_input" "$evidence_path" "$request_dir/prime" 1)"
            request_json_steady="$(write_trustmee_request_artifacts "$request_input" "$evidence_path" "$request_dir/steady-state" 0)"
            ;;
        *)
            die "unsupported request kind: $request_kind"
            ;;
    esac

    CURRENT_AS_PID="$(start_restful_as_background "$BINARY_PATH" "$port" "$work_root" "$log_file")"

    if ! run_request_sample "$port" "$request_json_prime" "$responses_dir" "$csv_path" "prime" 0; then
        OVERALL_FAILURES=$((OVERALL_FAILURES + 1))
    fi

    local i
    for ((i = 1; i <= WARMUP; i++)); do
        if ! run_request_sample "$port" "$request_json_steady" "$responses_dir" "$csv_path" "warmup" "$i"; then
            OVERALL_FAILURES=$((OVERALL_FAILURES + 1))
        fi
    done

    for ((i = 1; i <= ITERATIONS; i++)); do
        if ! run_request_sample "$port" "$request_json_steady" "$responses_dir" "$csv_path" "measure" "$i"; then
            OVERALL_FAILURES=$((OVERALL_FAILURES + 1))
        fi
    done

    stop_background_process "$CURRENT_AS_PID"
    CURRENT_AS_PID=""

    local config_path="$work_root/as-config.json"
    write_scenario_summary "$scenario" "$scenario_dir" "$csv_path" "$component_label" "$evidence_path" "$note_text" "$config_path" "$request_json_prime" "$request_json_steady"
    collect_comparison_summary "$scenario_dir/$scenario.summary.txt"
}

run_fresh_process_scenario() {
    local scenario="$1"
    local port="$2"
    local request_kind="$3"
    local request_input="$4"
    local component_label="$5"
    local evidence_path="$6"
    local note_text="$7"

    local scenario_dir
    scenario_dir="$(ensure_directory_absolute "$RUN_ROOT/$scenario")"
    local responses_dir="$scenario_dir/responses"
    local request_dir="$scenario_dir/request-artifacts"
    local csv_path="$scenario_dir/$scenario.samples.csv"
    local log_file="$scenario_dir/restful-as.log"
    local shared_component_cache_dir
    shared_component_cache_dir="$(ensure_directory_absolute "$scenario_dir/shared-component-cache")"
    mkdir -p "$responses_dir"
    record_csv_header "$csv_path"

    local request_json_prime
    local request_json_steady
    case "$request_kind" in
        native)
            request_json_prime="$(write_native_snp_request_artifacts "$evidence_path" "$request_dir")"
            request_json_steady="$request_json_prime"
            ;;
        trustmee)
            request_json_prime="$(write_trustmee_request_artifacts "$request_input" "$evidence_path" "$request_dir/prime" 1)"
            request_json_steady="$(write_trustmee_request_artifacts "$request_input" "$evidence_path" "$request_dir/steady-state" 0)"
            ;;
        *)
            die "unsupported request kind: $request_kind"
            ;;
    esac

    local total_prime_and_samples=$((1 + WARMUP + ITERATIONS))
    local sample_index
    local summary_config_path=""
    for ((sample_index = 0; sample_index < total_prime_and_samples; sample_index++)); do
        local sample_port=$((port + sample_index))
        local sample_work_root="$scenario_dir/service-state/$(printf 'sample-%03d' "$sample_index")"
        CURRENT_AS_PID="$(start_restful_as_background "$BINARY_PATH" "$sample_port" "$sample_work_root" "$log_file" "$DEFAULT_POLICY_SOURCE_DIR" "$shared_component_cache_dir")"
        if [[ -z "$summary_config_path" ]]; then
            summary_config_path="$sample_work_root/as-config.json"
        fi

        local phase
        local iteration
        if (( sample_index == 0 )); then
            phase="prime"
            iteration=0
        elif (( sample_index <= WARMUP )); then
            phase="warmup"
            iteration="$sample_index"
        else
            phase="measure"
            iteration=$((sample_index - WARMUP))
        fi

        local request_json="$request_json_steady"
        if (( sample_index == 0 )); then
            request_json="$request_json_prime"
        fi

        if ! run_request_sample "$sample_port" "$request_json" "$responses_dir" "$csv_path" "$phase" "$iteration"; then
            OVERALL_FAILURES=$((OVERALL_FAILURES + 1))
        fi

        stop_background_process "$CURRENT_AS_PID"
        CURRENT_AS_PID=""
    done

    write_scenario_summary "$scenario" "$scenario_dir" "$csv_path" "$component_label" "$evidence_path" "$note_text" "$summary_config_path" "$request_json_prime" "$request_json_steady"
    collect_comparison_summary "$scenario_dir/$scenario.summary.txt"
}

NATIVE_EVIDENCE_PATH="$(canonicalize_existing_path "$DEFAULT_SNP_EVIDENCE_PATH")"
WASM_COMPONENT_PATH="$(canonicalize_existing_path "$DEFAULT_SNP_WASM_COMPONENT_PATH")"
WASM_HOST_CRYPTO_COMPONENT_PATH="$(canonicalize_existing_path "$DEFAULT_SNP_WASM_HOST_CRYPTO_COMPONENT_PATH")"

cat >"$COMPARISON_SUMMARY" <<EOF
run_root: $RUN_ROOT
binary: $BINARY_PATH
iterations: $ITERATIONS
warmup: $WARMUP
port_base: $PORT_BASE
requested_port_base: $REQUESTED_PORT_BASE
port_span: $TOTAL_PORT_SPAN

EOF

run_warm_process_scenario \
    "native_snp_warm_process" \
    "$NATIVE_WARM_PORT" \
    "native" \
    "" \
    "native-snp-verifier" \
    "$NATIVE_EVIDENCE_PATH" \
    "One long-lived Attestation Service process; repeated native SNP requests reuse the same process but not a Wasm component cache."

run_fresh_process_scenario \
    "native_snp_fresh_process" \
    "$NATIVE_FRESH_PORT_BASE" \
    "native" \
    "" \
    "native-snp-verifier" \
    "$NATIVE_EVIDENCE_PATH" \
    "Fresh Attestation Service process for every request; measurement excludes startup and readiness wait time."

run_fresh_process_scenario \
    "wasm_snp_disk_cache" \
    "$WASM_DISK_PORT_BASE" \
    "trustmee" \
    "$WASM_COMPONENT_PATH" \
    "$WASM_COMPONENT_PATH" \
    "$NATIVE_EVIDENCE_PATH" \
    "Prime request is stapled; later fresh-process requests are unstapled and reuse the scenario-local Wasm byte cache plus Wasmtime compiled cache files. Measurement excludes startup and readiness wait time."

run_warm_process_scenario \
    "wasm_snp_memory_cache" \
    "$WASM_MEMORY_PORT" \
    "trustmee" \
    "$WASM_COMPONENT_PATH" \
    "$WASM_COMPONENT_PATH" \
    "$NATIVE_EVIDENCE_PATH" \
    "Prime request is stapled; later long-lived-process requests are unstapled and reuse the in-memory compiled component cache without resolving Wasm bytes again."

run_warm_process_scenario \
    "wasm_snp_host_crypto_memory_cache" \
    "$WASM_HOST_CRYPTO_MEMORY_PORT" \
    "trustmee" \
    "$WASM_HOST_CRYPTO_COMPONENT_PATH" \
    "$WASM_HOST_CRYPTO_COMPONENT_PATH" \
    "$NATIVE_EVIDENCE_PATH" \
    "Prime request is stapled; later long-lived-process requests are unstapled and reuse the in-memory compiled host-crypto component cache without resolving Wasm bytes again."

log_note "benchmark run root: $RUN_ROOT"
log_note "comparison summary: $COMPARISON_SUMMARY"

if (( OVERALL_FAILURES > 0 )); then
    die "benchmark run recorded $OVERALL_FAILURES failed requests; inspect $RUN_ROOT"
fi
