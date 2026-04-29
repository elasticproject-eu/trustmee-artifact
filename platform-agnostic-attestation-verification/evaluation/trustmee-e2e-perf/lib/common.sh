#!/usr/bin/env bash

set -euo pipefail

trustmee_e2e_perf_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [[ -h "$source" ]]; do
        local dir
        dir="$(cd "$(dirname "$source")" && pwd)"
        source="$(readlink "$source")"
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    cd "$(dirname "$source")" && pwd
}

readonly TRUSTMEE_E2E_PERF_LIB_DIR="$(trustmee_e2e_perf_script_dir)"
readonly TRUSTMEE_E2E_PERF_ROOT="$(cd "$TRUSTMEE_E2E_PERF_LIB_DIR/.." && pwd)"
readonly TRUSTMEE_REPO_ROOT="$(cd "$TRUSTMEE_E2E_PERF_ROOT/../.." && pwd)"
readonly TRUSTMEE_TEST_DATA_ROOT="$TRUSTMEE_REPO_ROOT/test_data/trustmee-lib"
readonly TRUSTMEE_SIGNATURE_DEMO_ROOT="$TRUSTMEE_TEST_DATA_ROOT/signature-demo"
readonly DEFAULT_POLICY_SOURCE_DIR="$TRUSTMEE_REPO_ROOT/attestation-service/tests/coco-as/policy"
readonly DEFAULT_RESULTS_ROOT="$TRUSTMEE_E2E_PERF_ROOT/results"
readonly DEFAULT_SNP_EVIDENCE_PATH="$TRUSTMEE_TEST_DATA_ROOT/snp_evidence.json"
readonly DEFAULT_SNP_WASM_COMPONENT_PATH="$TRUSTMEE_TEST_DATA_ROOT/snp_verifier_component.wasm"
readonly DEFAULT_SNP_WASM_HOST_CRYPTO_COMPONENT_PATH="$TRUSTMEE_TEST_DATA_ROOT/snp_verifier_host_crypto_component.wasm"
readonly DEFAULT_SIGNED_SNP_WASM_COMPONENT_PATH="$TRUSTMEE_SIGNATURE_DEMO_ROOT/snp_verifier_component.signed.wasm"
readonly DEFAULT_SIGNED_SNP_TRUST_STORE_PATH="$TRUSTMEE_SIGNATURE_DEMO_ROOT/snp_verifier_component.trust-store.json"
readonly RESTFUL_AS_FEATURES="restful-bin,snp-verifier,wasm-verification-component-driver"
readonly TRUSTMEE_EAT_PROFILE_URL="https://trustmee.invalid/eat/component-evidence"
readonly TRUSTMEE_COLLECTION_TYPE_URL="https://trustmee.invalid/cmw/verification-input"
readonly TRUSTMEE_EAT_MEDIA_TYPE="application/eat-ucs+json; eat_profile=\"https://trustmee.invalid/eat/component-evidence\""
readonly TRUSTMEE_WASM_MEDIA_TYPE="application/wasm"

log_note() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

die() {
    log_note "error: $*"
    exit 1
}

require_tool() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
}

ensure_common_prereqs() {
    require_tool awk
    require_tool base64
    require_tool cargo
    require_tool cp
    require_tool curl
    require_tool date
    require_tool jq
    require_tool sha256sum
    require_tool timeout

    [[ -d "$TRUSTMEE_REPO_ROOT" ]] || die "repo root not found: $TRUSTMEE_REPO_ROOT"
    [[ -d "$TRUSTMEE_TEST_DATA_ROOT" ]] || die "test data dir not found: $TRUSTMEE_TEST_DATA_ROOT"
    [[ -d "$DEFAULT_POLICY_SOURCE_DIR" ]] || die "policy source dir not found: $DEFAULT_POLICY_SOURCE_DIR"
}

timestamp_utc() {
    date -u +%Y%m%dT%H%M%SZ
}

ensure_directory_absolute() {
    local dir="$1"
    mkdir -p "$dir"
    (
        cd "$dir" && pwd
    )
}

canonicalize_existing_path() {
    local path="$1"
    [[ -e "$path" ]] || die "path does not exist: $path"
    (
        cd "$(dirname "$path")" && printf '%s/%s\n' "$(pwd)" "$(basename "$path")"
    )
}

b64url_file() {
    local path="$1"
    base64 -w0 "$path" | tr '+/' '-_' | tr -d '=\n'
}

sha256_hex_file() {
    local path="$1"
    sha256sum "$path" | awk '{print $1}'
}

component_id_for_file() {
    local path="$1"
    printf 'component-%s\n' "$(sha256_hex_file "$path")"
}

restful_as_binary_path() {
    local use_release="${1:-0}"
    local profile="debug"
    if [[ "$use_release" == "1" ]]; then
        profile="release"
    fi
    printf '%s/target/%s/restful-as\n' "$TRUSTMEE_REPO_ROOT" "$profile"
}

build_restful_as() {
    local use_release="${1:-0}"
    local -a args=(
        build
        --manifest-path "$TRUSTMEE_REPO_ROOT/Cargo.toml"
        -p attestation-service
        --no-default-features
        --features "$RESTFUL_AS_FEATURES"
        --bin restful-as
    )
    if [[ "$use_release" == "1" ]]; then
        args+=(--release)
    fi
    cargo "${args[@]}"
    restful_as_binary_path "$use_release"
}

copy_policy_bundle() {
    local source_dir="$1"
    local dest_dir="$2"
    mkdir -p "$dest_dir"
    cp -a "$source_dir"/. "$dest_dir"/
}

write_as_config() {
    local work_root="$1"
    local policy_source_dir="${2:-$DEFAULT_POLICY_SOURCE_DIR}"
    local component_cache_base_dir="${3:-}"
    local component_trust_store="${4:-}"
    local abs_work_root
    abs_work_root="$(ensure_directory_absolute "$work_root")"
    local policy_dir="$abs_work_root/policy"
    local abs_component_cache_base_dir
    local abs_component_trust_store=""

    copy_policy_bundle "$policy_source_dir" "$policy_dir"
    mkdir -p \
        "$abs_work_root/work" \
        "$abs_work_root/reference_values"

    if [[ -n "$component_cache_base_dir" ]]; then
        abs_component_cache_base_dir="$(ensure_directory_absolute "$component_cache_base_dir")"
    else
        abs_component_cache_base_dir="$abs_work_root/component-cache"
        mkdir -p "$abs_component_cache_base_dir"
    fi

    if [[ -n "$component_trust_store" ]]; then
        abs_component_trust_store="$(canonicalize_existing_path "$component_trust_store")"
    fi

    local config_path="$abs_work_root/as-config.json"
    jq -n \
        --arg work_dir "$abs_work_root/work" \
        --arg rvps_path "$abs_work_root/reference_values" \
        --arg policy_dir "$policy_dir" \
        --arg component_cache_base_dir "$abs_component_cache_base_dir" \
        --arg component_trust_store "$abs_component_trust_store" \
        '{
            work_dir: $work_dir,
            rvps_config: {
                type: "BuiltIn",
                storage: {
                    type: "LocalFs",
                    file_path: $rvps_path
                }
            },
            attestation_token_broker: {
                policy_dir: $policy_dir
            },
            wasm_component_registry: {
                component_cache_base_dir: $component_cache_base_dir
            }
        }
        | if $component_trust_store != "" then
            .wasm_component_registry.component_trust_store = $component_trust_store
          else
            .
          end' >"$config_path"

    printf '%s\n' "$config_path"
}

wait_for_as() {
    local port="$1"
    local timeout_secs="${2:-60}"
    local pid="${3:-}"
    local start_time="$SECONDS"
    while (( SECONDS - start_time < timeout_secs )); do
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
            return 2
        fi
        local code
        code="$(
            curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/policy" 2>/dev/null || true
        )"
        if [[ "$code" == "200" ]]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

stop_background_process() {
    local pid="$1"
    if [[ -z "$pid" ]]; then
        return 0
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

start_restful_as_background() {
    local binary_path="$1"
    local port="$2"
    local work_root="$3"
    local log_file="$4"
    local policy_source_dir="${5:-$DEFAULT_POLICY_SOURCE_DIR}"
    local component_cache_base_dir="${6:-}"
    local component_trust_store="${7:-}"

    local config_path
    config_path="$(write_as_config "$work_root" "$policy_source_dir" "$component_cache_base_dir" "$component_trust_store")"
    mkdir -p "$(dirname "$log_file")"

    (
        printf '=== start %s port=%s work_root=%s config=%s ===\n' \
            "$(timestamp_utc)" "$port" "$work_root" "$config_path"
        cd "$work_root"
        exec env RUST_LOG="${RUST_LOG:-info,restful_as=debug,attestation_service=info}" \
            "$binary_path" \
            --config-file "$config_path" \
            --socket "127.0.0.1:$port"
    ) >>"$log_file" 2>&1 &

    local pid=$!
    if ! wait_for_as "$port" 60 "$pid"; then
        stop_background_process "$pid"
        tail -n 50 "$log_file" >&2 || true
        die "restful-as failed to become ready on port $port"
    fi

    printf '%s\n' "$pid"
}

write_trustmee_request_artifacts() {
    local component_path="$1"
    local evidence_path="$2"
    local output_dir="$3"
    local include_stapled_component="${4:-1}"

    mkdir -p "$output_dir"

    local component_id
    component_id="$(component_id_for_file "$component_path")"
    printf '%s\n' "$component_id" >"$output_dir/component-id.txt"

    b64url_file "$evidence_path" >"$output_dir/snp-evidence.b64"
    if [[ "$include_stapled_component" == "1" ]]; then
        b64url_file "$component_path" >"$output_dir/verifier-component.b64"
    fi

    jq -n \
        --arg eat_profile "$TRUSTMEE_EAT_PROFILE_URL" \
        --arg component_id "$component_id" \
        --arg evidence_type "application/json" \
        --rawfile evidence "$output_dir/snp-evidence.b64" \
        '{
            eat_profile: $eat_profile,
            component_id: $component_id,
            evidence_type: $evidence_type,
            evidence: $evidence
        }' >"$output_dir/trustmee-eat.json"

    b64url_file "$output_dir/trustmee-eat.json" >"$output_dir/trustmee-eat.b64"

    if [[ "$include_stapled_component" == "1" ]]; then
        jq -n \
            --arg collection_type "$TRUSTMEE_COLLECTION_TYPE_URL" \
            --arg eat_mt "$TRUSTMEE_EAT_MEDIA_TYPE" \
            --rawfile eat_payload "$output_dir/trustmee-eat.b64" \
            --arg wasm_mt "$TRUSTMEE_WASM_MEDIA_TYPE" \
            --rawfile wasm_payload "$output_dir/verifier-component.b64" \
            '{
                "__cmwc_t": $collection_type,
                "evidence": [$eat_mt, $eat_payload, 4],
                "verifier": [$wasm_mt, $wasm_payload, 2]
            }' >"$output_dir/input.cmw"
    else
        jq -n \
            --arg collection_type "$TRUSTMEE_COLLECTION_TYPE_URL" \
            --arg eat_mt "$TRUSTMEE_EAT_MEDIA_TYPE" \
            --rawfile eat_payload "$output_dir/trustmee-eat.b64" \
            '{
                "__cmwc_t": $collection_type,
                "evidence": [$eat_mt, $eat_payload, 4]
            }' >"$output_dir/input.cmw"
    fi

    b64url_file "$output_dir/input.cmw" >"$output_dir/input.cmw.b64"

    jq -n \
        --rawfile evidence "$output_dir/input.cmw.b64" \
        '{
            verification_requests: [{
                tee: "sample",
                evidence: $evidence
            }],
            policy_ids: ["default"]
        }' >"$output_dir/attest-trustmee.json"

    printf '%s\n' "$output_dir/attest-trustmee.json"
}

write_native_snp_request_artifacts() {
    local evidence_path="$1"
    local output_dir="$2"

    mkdir -p "$output_dir"

    b64url_file "$evidence_path" >"$output_dir/snp-native-evidence.b64"

    jq -n \
        --rawfile evidence "$output_dir/snp-native-evidence.b64" \
        '{
            verification_requests: [{
                tee: "snp",
                evidence: $evidence
            }],
            policy_ids: ["default"]
        }' >"$output_dir/attest-native-snp.json"

    printf '%s\n' "$output_dir/attest-native-snp.json"
}

send_request_with_timing() {
    local port="$1"
    local request_json="$2"
    local response_path="$3"
    local headers_path="$4"

    local curl_output
    if ! curl_output="$(
        curl -sS \
            -D "$headers_path" \
            -o "$response_path" \
            -w '%{http_code} %{time_total}' \
            -X POST "http://127.0.0.1:$port/attestation" \
            -H 'Content-Type: application/json' \
            --data-binary @"$request_json"
    )"; then
        printf '000 0.000 0\n'
        return 1
    fi

    local http_code time_total
    read -r http_code time_total <<<"$curl_output"
    local time_ms
    time_ms="$(awk -v seconds="$time_total" 'BEGIN { printf "%.3f", seconds * 1000 }')"
    local token_bytes
    token_bytes="$(wc -c <"$response_path" | awk '{print $1}')"
    printf '%s %s %s\n' "$http_code" "$time_ms" "$token_bytes"
}

measurement_stats_from_csv() {
    local csv_path="$1"
    awk -F, '
        NR == 1 { next }
        $1 == "measure" {
            count++
            value = $4 + 0
            sum += value
            if (count == 1 || value < min) {
                min = value
            }
            if (count == 1 || value > max) {
                max = value
            }
        }
        END {
            if (count == 0) {
                exit 1
            }
            printf "%.3f %.3f %.3f %d\n", sum / count, min, max, count
        }
    ' "$csv_path"
}

success_failure_counts_from_csv() {
    local csv_path="$1"
    awk -F, '
        NR == 1 { next }
        {
            if ($3 == "200" && ($5 + 0) > 0) {
                success++
            } else {
                failure++
            }
        }
        END {
            printf "%d %d\n", success + 0, failure + 0
        }
    ' "$csv_path"
}

phase_time_from_csv() {
    local csv_path="$1"
    local phase_name="$2"
    awk -F, -v phase_name="$phase_name" '
        NR == 1 { next }
        $1 == phase_name {
            printf "%s\n", $4
            found = 1
            exit 0
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$csv_path"
}
