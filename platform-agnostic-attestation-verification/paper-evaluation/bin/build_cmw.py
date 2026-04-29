#!/usr/bin/env python3
"""Build a CMW-based REST attestation body.

Produces a JSON file that `eval_latency.py` can POST to /attestation 50 times
without rebuilding the CMW per request.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

TRUSTMEE_COLLECTION_TYPE = "https://trustmee.invalid/cmw/verification-input"
TRUSTMEE_EAT_PROFILE = "https://trustmee.invalid/eat/component-evidence"
WASM_MEDIA_TYPE = "application/wasm"
EAT_JSON_MEDIA_TYPE = "application/eat-ucs+json"
EAT_CBOR_MEDIA_TYPE = "application/eat-ucs+cbor"
EVIDENCE_LABEL = "evidence"
VERIFIER_LABEL = "verifier"
CMW_INDICATOR_ENDORSEMENT = 2
CMW_INDICATOR_EVIDENCE = 4

CBOR_KEY_EAT_PROFILE = 265
CBOR_KEY_COMPONENT_ID = 65537
CBOR_KEY_EVIDENCE_TYPE = 65538
CBOR_KEY_EVIDENCE = 65539


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--attestation-input-cli",
        required=True,
        help="Path to the compiled attestation-input-for-trustmee binary",
    )
    ap.add_argument(
        "--cmw-format",
        choices=["json", "cbor"],
        default="json",
        help="CMW/EAT wire format to wrap inside the REST evidence field",
    )
    ap.add_argument("--tee", required=True, choices=["sgx", "snp", "tdx"])
    ap.add_argument("--evidence", required=True, help="Evidence file path")
    component_ref = ap.add_mutually_exclusive_group(required=True)
    component_ref.add_argument("--component", help="Wasm verifier component path")
    component_ref.add_argument("--component-id", help="Pre-cached Wasm verifier component id")
    ap.add_argument(
        "--endorsement",
        action="append",
        default=[],
        help="LABEL:MEDIA_TYPE:PATH (may be repeated)",
    )
    ap.add_argument("--policy-id", default="default")
    ap.add_argument("--output", required=True, help="Where to write the REST body JSON")
    return ap.parse_args()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def component_id_for(component: bytes) -> str:
    return f"component-{hashlib.sha256(component).hexdigest()}"


def parse_endorsement(value: str) -> tuple[str, str, bytes]:
    try:
        label, media_type, path = value.split(":", 2)
    except ValueError as err:
        raise ValueError(f"invalid endorsement `{value}`; expected LABEL:MEDIA_TYPE:PATH") from err
    if not label or not media_type or not path:
        raise ValueError(f"invalid endorsement `{value}`; expected LABEL:MEDIA_TYPE:PATH")
    return label, media_type, Path(path).read_bytes()


def build_json_with_attestation_input_cli(args: argparse.Namespace) -> int:
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        args.attestation_input_cli,
        "--mode",
        "rest",
        "--tee",
        args.tee,
        "--evidence",
        args.evidence,
        "--policy-id",
        args.policy_id,
        "--compact",
        "--output-file",
        args.output,
    ]
    if args.component:
        cmd.extend(["--component", args.component])
    else:
        cmd.extend(["--component-id", args.component_id])
    for endorsement in args.endorsement:
        cmd.extend(["--endorsement", endorsement])

    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, check=False)
    return result.returncode


def build_cbor_rest_body(args: argparse.Namespace) -> dict:
    try:
        import cbor2
    except ImportError as err:
        raise RuntimeError(
            "Python package `cbor2` is required for --cmw-format cbor"
        ) from err

    evidence = Path(args.evidence).read_bytes()
    component_bytes = Path(args.component).read_bytes() if args.component else None
    component_id = args.component_id or component_id_for(component_bytes or b"")

    eat = {
        CBOR_KEY_EAT_PROFILE: TRUSTMEE_EAT_PROFILE,
        CBOR_KEY_COMPONENT_ID: component_id,
        CBOR_KEY_EVIDENCE_TYPE: "application/octet-stream",
        CBOR_KEY_EVIDENCE: evidence,
    }
    eat_payload = cbor2.dumps(eat, canonical=True)

    cmw = {
        "__cmwc_t": TRUSTMEE_COLLECTION_TYPE,
        EVIDENCE_LABEL: [
            f'{EAT_CBOR_MEDIA_TYPE}; eat_profile="{TRUSTMEE_EAT_PROFILE}"',
            eat_payload,
            CMW_INDICATOR_EVIDENCE,
        ],
    }
    if component_bytes is not None:
        cmw[VERIFIER_LABEL] = [
            WASM_MEDIA_TYPE,
            component_bytes,
            CMW_INDICATOR_ENDORSEMENT,
        ]

    for endorsement in args.endorsement:
        label, media_type, payload = parse_endorsement(endorsement)
        cmw[label] = [media_type, payload, CMW_INDICATOR_ENDORSEMENT]

    cmw_payload = cbor2.dumps(cmw, canonical=True)
    return {
        "verification_requests": [
            {
                "tee": "sample",
                "evidence": b64url(cmw_payload),
            }
        ],
        "policy_ids": [args.policy_id],
    }


def main() -> int:
    args = parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    if args.cmw_format == "json":
        return build_json_with_attestation_input_cli(args)

    try:
        body = build_cbor_rest_body(args)
    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(body, f, separators=(",", ":"))
        f.write("\n")
    print(f"wrote CBOR CMW REST body to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
