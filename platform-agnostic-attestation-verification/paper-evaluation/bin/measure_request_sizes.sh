#!/usr/bin/env bash
# Build representative attestation REST bodies (native vs wasm-stapled vs
# wasm-component-id-only, for SNP, TDX, and SGX) and write their byte sizes as
# JSON alongside the rest of the eval results.
#
# Output:
#   $RESULTS_DIR/request_sizes.json
#   $RESULTS_DIR/request_size_requests/*.body.json
#
# Run order assumption: this is invoked from run_all.sh AFTER build_artifacts.sh
# (so the wasm components, attestation-input-format CLI, and
# fetch-tdx-collateral helper exist).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAPER_EVAL_ROOT="${PAPER_EVAL_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REPO_ROOT="${REPO_ROOT:-$(cd "$PAPER_EVAL_ROOT/.." && pwd)}"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$PAPER_EVAL_ROOT/results}"
TMP_DIR="${TMP_DIR:-$PAPER_EVAL_ROOT/tmp}"
RUNS="${RUNS:-50}"
PORT="${PORT:-18080}"
export PAPER_EVAL_ROOT REPO_ROOT WORKSPACE_ROOT RESULTS_DIR TMP_DIR RUNS PORT

source "$SCRIPT_DIR/eval_env.sh"

OUT_JSON="${1:-$RESULTS_DIR/request_sizes.json}"
REQUEST_DUMP_DIR="${REQUEST_DUMP_DIR:-$(dirname "$OUT_JSON")/request_size_requests}"
SIZE_TMP="$TMP_DIR/request_sizes"
rm -rf "$SIZE_TMP"
mkdir -p "$SIZE_TMP"

echo "== measuring attestation request body sizes =="

# --- native bodies --------------------------------------------------------
build_snp_native_body "$SIZE_TMP/snp_native_no_collateral.body.json" 0
build_snp_native_body "$SIZE_TMP/snp_native_with_collateral.body.json" 1
build_tdx_native_body "$SIZE_TMP/tdx_native_no_collateral.body.json"
build_sgx_native_body "$SIZE_TMP/sgx_native_no_collateral.body.json"
ensure_tdx_collateral_cbor
ensure_sgx_collateral_cbor

# --- wasm bodies with stapled component (full wasm bytes in CMW) ---------
build_snp_wasm_body "$SNP_WASM" "$SIZE_TMP/snp_wasm_stapled_no_collateral.body.json" 0 component
build_snp_wasm_body "$SNP_WASM" "$SIZE_TMP/snp_wasm_stapled_with_collateral.body.json" 1 component
build_tdx_wasm_body              "$SIZE_TMP/tdx_wasm_stapled_no_collateral.body.json" 0 component
build_tdx_wasm_body              "$SIZE_TMP/tdx_wasm_stapled_with_collateral.body.json" 1 component
build_sgx_wasm_body              "$SIZE_TMP/sgx_wasm_stapled_no_collateral.body.json" 0 component
build_sgx_wasm_body              "$SIZE_TMP/sgx_wasm_stapled_with_collateral.body.json" 1 component

# --- wasm bodies with component-id only (assumes AS has the wasm cached) -
build_snp_wasm_body "$SNP_WASM" "$SIZE_TMP/snp_wasm_component_id_no_collateral.body.json" 0 component-id
build_snp_wasm_body "$SNP_WASM" "$SIZE_TMP/snp_wasm_component_id_with_collateral.body.json" 1 component-id
build_tdx_wasm_body              "$SIZE_TMP/tdx_wasm_component_id_no_collateral.body.json" 0 component-id
build_tdx_wasm_body              "$SIZE_TMP/tdx_wasm_component_id_with_collateral.body.json" 1 component-id
build_sgx_wasm_body              "$SIZE_TMP/sgx_wasm_component_id_no_collateral.body.json" 0 component-id
build_sgx_wasm_body              "$SIZE_TMP/sgx_wasm_component_id_with_collateral.body.json" 1 component-id

# --- aggregate request body sizes and save exact comparison requests ------
python3 - "$SIZE_TMP" "$TDX_COLLATERAL_CBOR" "$SGX_COLLATERAL_CBOR" "$OUT_JSON" "$REQUEST_DUMP_DIR" <<'PY'
import base64
import hashlib
import json
import os
import shutil
import sys

tmp_dir, tdx_collateral_cbor, sgx_collateral_cbor, out_json, request_dump_dir = sys.argv[1:6]

def sz(path: str) -> int:
    return os.path.getsize(path)

def body(name: str) -> int:
    return sz(os.path.join(tmp_dir, f"{name}.body.json"))

def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def native_with_collateral_estimate(tee: str, collateral_cbor: str) -> dict:
    """Estimate native Intel if collateral had to travel in REST JSON.

    Native TDX/SGX do not currently support stapled collateral in the REST
    evidence object. For request-size accounting, model a synthetic native
    evidence field containing standard-base64 collateral bytes, then encode
    that evidence JSON through the same outer base64url REST field used by the
    native Intel request today.
    """
    body_path = os.path.join(tmp_dir, f"{tee}_native_no_collateral.body.json")
    with open(body_path, "r", encoding="utf-8") as f:
        native_body = json.load(f)

    evidence_b64 = native_body["verification_requests"][0]["evidence"]
    evidence = json.loads(b64url_decode(evidence_b64))

    with open(collateral_cbor, "rb") as f:
        collateral = f.read()

    collateral_field = f"{tee}_collateral_cbor"
    collateral_b64 = base64.b64encode(collateral).decode("ascii")
    evidence[collateral_field] = collateral_b64
    encoded_evidence = b64url_encode(
        json.dumps(evidence, separators=(",", ":")).encode("utf-8")
    )
    size = sz(body_path) + len(encoded_evidence) - len(evidence_b64)

    return {
        "bytes": size,
        "formula": (
            f"{tee}.native.no_collateral + delta(base64url(JSON evidence with "
            f"standard-base64 {collateral_field} field))"
        ),
        "synthetic_field": collateral_field,
        f"{tee}_native_no_collateral": sz(body_path),
        f"{tee}_collateral_cbor": len(collateral),
        f"{tee}_collateral_base64": len(collateral_b64),
        "native_evidence_base64_before": len(evidence_b64),
        "native_evidence_base64_after": len(encoded_evidence),
        "native_evidence_base64_delta": len(encoded_evidence) - len(evidence_b64),
    }

def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

inspection_requests = [
    ("snp", "native", "no_collateral", "snp_native_no_collateral"),
    ("snp", "wasm_component_id", "no_collateral", "snp_wasm_component_id_no_collateral"),
    ("tdx", "native", "no_collateral", "tdx_native_no_collateral"),
    ("tdx", "wasm_component_id", "no_collateral", "tdx_wasm_component_id_no_collateral"),
    ("sgx", "native", "no_collateral", "sgx_native_no_collateral"),
    ("sgx", "wasm_component_id", "no_collateral", "sgx_wasm_component_id_no_collateral"),
]

os.makedirs(request_dump_dir, exist_ok=True)
manifest = {
    "note": "Exact compact REST request bodies used for the no-collateral native baseline vs component-id size comparison.",
    "unit": "bytes",
    "cmw_format": os.environ.get("TRUSTMEE_CMW_FORMAT", "cbor"),
    "requests": [],
}
for tee, verifier, collateral, name in inspection_requests:
    src = os.path.join(tmp_dir, f"{name}.body.json")
    dst_name = f"{name}.body.json"
    dst = os.path.join(request_dump_dir, dst_name)
    shutil.copyfile(src, dst)
    manifest["requests"].append({
        "tee": tee,
        "verifier": verifier,
        "collateral": collateral,
        "file": dst_name,
        "bytes": sz(dst),
        "sha256": sha256(dst),
    })

manifest_path = os.path.join(request_dump_dir, "manifest.json")
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

tdx_native_no_collateral = body("tdx_native_no_collateral")
tdx_collateral_bytes = sz(tdx_collateral_cbor)
tdx_native_with_collateral = native_with_collateral_estimate("tdx", tdx_collateral_cbor)
sgx_native_no_collateral = body("sgx_native_no_collateral")
sgx_collateral_bytes = sz(sgx_collateral_cbor)
sgx_native_with_collateral = native_with_collateral_estimate("sgx", sgx_collateral_cbor)

result = {
    "unit": "bytes",
    "cmw_format": os.environ.get("TRUSTMEE_CMW_FORMAT", "cbor"),
    "inspection_requests": {
        "directory": request_dump_dir,
        "manifest": manifest_path,
    },
    "request_bodies": {
        "snp": {
            "native": {
                "no_collateral": body("snp_native_no_collateral"),
                "with_collateral": body("snp_native_with_collateral"),
            },
            "wasm_component_id": {
                "no_collateral": body("snp_wasm_component_id_no_collateral"),
                "with_collateral": body("snp_wasm_component_id_with_collateral"),
            },
            "wasm_stapled": {
                "no_collateral": body("snp_wasm_stapled_no_collateral"),
                "with_collateral": body("snp_wasm_stapled_with_collateral"),
            },
        },
        "tdx": {
            "native": {
                "no_collateral": tdx_native_no_collateral,
                "with_collateral": tdx_native_with_collateral["bytes"],
            },
            "wasm_component_id": {
                "no_collateral": body("tdx_wasm_component_id_no_collateral"),
                "with_collateral": body("tdx_wasm_component_id_with_collateral"),
            },
            "wasm_stapled": {
                "no_collateral": body("tdx_wasm_stapled_no_collateral"),
                "with_collateral": body("tdx_wasm_stapled_with_collateral"),
            },
        },
        "sgx": {
            "native": {
                "no_collateral": sgx_native_no_collateral,
                "with_collateral": sgx_native_with_collateral["bytes"],
            },
            "wasm_component_id": {
                "no_collateral": body("sgx_wasm_component_id_no_collateral"),
                "with_collateral": body("sgx_wasm_component_id_with_collateral"),
            },
            "wasm_stapled": {
                "no_collateral": body("sgx_wasm_stapled_no_collateral"),
                "with_collateral": body("sgx_wasm_stapled_with_collateral"),
            },
        },
    },
    "estimates": {
        "tdx.native.with_collateral": {
            **tdx_native_with_collateral,
            "previous_raw_addition_estimate": {
                "formula": "tdx.native.no_collateral + tdx_collateral_cbor",
                "bytes": tdx_native_no_collateral + tdx_collateral_bytes,
                "tdx_native_no_collateral": tdx_native_no_collateral,
                "tdx_collateral_cbor": tdx_collateral_bytes,
            },
        },
        "sgx.native.with_collateral": {
            **sgx_native_with_collateral,
            "previous_raw_addition_estimate": {
                "formula": "sgx.native.no_collateral + sgx_collateral_cbor",
                "bytes": sgx_native_no_collateral + sgx_collateral_bytes,
                "sgx_native_no_collateral": sgx_native_no_collateral,
                "sgx_collateral_cbor": sgx_collateral_bytes,
            },
        },
    },
}

os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
    f.write("\n")

print(f"wrote {out_json}")
print(f"wrote exact comparison requests under {request_dump_dir}")
PY
