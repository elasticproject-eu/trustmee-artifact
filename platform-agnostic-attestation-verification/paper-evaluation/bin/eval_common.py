"""Shared helpers for paper-evaluation python scripts.

The attestation-service (new code) takes this REST body shape for /attestation:

    {
      "verification_requests": [
        { "tee": "sgx"|"snp"|"tdx",
          "evidence": "<base64url>" }
      ],
      "policy_ids": ["default"]
    }

For the wasm verifier, set `tee` to `sample`; the evidence is a base64url-encoded CMW that includes a
component id or a stapled wasm component, plus any endorsements (e.g. SNP cert
chain, TDX collateral).
Pre-built REST bodies are read from disk and POSTed as-is.
"""

from __future__ import annotations

import base64
import json
import pathlib
import urllib.error
import urllib.request


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_snp_native_body(
    evidence_json_path: str,
    include_cert_chain: bool,
) -> dict:
    """REST body for native SNP verifier."""
    payload = load_json(evidence_json_path)
    if not include_cert_chain:
        payload.pop("cert_chain", None)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        "verification_requests": [
            {
                "tee": "snp",
                "evidence": b64url(raw),
            }
        ],
        "policy_ids": ["default"],
    }


def build_tdx_native_body(quote_path: str, ccel_path: str | None = None) -> dict:
    """REST body for native TDX verifier."""
    with open(quote_path, "rb") as f:
        quote = f.read()
    ccel_b64 = None
    if ccel_path:
        with open(ccel_path, "rb") as f:
            ccel_b64 = b64std(f.read())
    evidence = {"quote": b64std(quote), "cc_eventlog": ccel_b64}
    raw = json.dumps(evidence, separators=(",", ":")).encode("utf-8")
    return {
        "verification_requests": [
            {
                "tee": "tdx",
                "evidence": b64url(raw),
            }
        ],
        "policy_ids": ["default"],
    }


def build_sgx_native_body(quote_path: str) -> dict:
    """REST body for native SGX verifier."""
    with open(quote_path, "rb") as f:
        quote = f.read()
    evidence = {"quote": b64std(quote)}
    raw = json.dumps(evidence, separators=(",", ":")).encode("utf-8")
    return {
        "verification_requests": [
            {
                "tee": "sgx",
                "evidence": b64url(raw),
            }
        ],
        "policy_ids": ["default"],
    }


def post_json(url: str, payload: dict, timeout: float = 120.0) -> tuple[int, bytes]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def repo_root() -> pathlib.Path:
    """Path to platform-agnostic-attestation-verification/."""
    here = pathlib.Path(__file__).resolve()
    return here.parents[2]


def workspace_root() -> pathlib.Path:
    """Path to the parent of platform-agnostic-attestation-verification/ that
    also contains trustmee-verification-library/ and
    wasm-verification-components/."""
    return repo_root().parent


def paper_eval_root() -> pathlib.Path:
    return repo_root() / "paper-evaluation"


def default_snp_evidence_path() -> str:
    return str(repo_root() / "test_data" / "trustmee-lib" / "snp_evidence.json")


def default_tdx_quote_path() -> str:
    return str(repo_root() / "test_data" / "trustmee-lib" / "tdx_quote.bin")


def default_snp_component_path() -> str:
    return str(repo_root() / "test_data" / "trustmee-lib" / "snp_verifier_component.wasm")


def default_snp_host_crypto_component_path() -> str:
    return str(
        repo_root() / "test_data" / "trustmee-lib" / "snp_verifier_host_crypto_component.wasm"
    )


def default_tdx_component_path() -> str:
    return str(repo_root() / "test_data" / "trustmee-lib" / "tdx_verifier_component.wasm")
