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


def build_snp_evidence(evidence_json_path: str, include_cert_chain: bool) -> str:
    payload = load_json(evidence_json_path)
    if not include_cert_chain:
        payload.pop("cert_chain", None)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return b64url(raw)


def build_tdx_evidence(quote_path: str, ccel_path: str | None) -> str:
    with open(quote_path, "rb") as f:
        quote = f.read()
    ccel_b64 = None
    if ccel_path:
        with open(ccel_path, "rb") as f:
            ccel_b64 = b64std(f.read())
    evidence = {"quote": b64std(quote), "cc_eventlog": ccel_b64}
    raw = json.dumps(evidence, separators=(",", ":")).encode("utf-8")
    return b64url(raw)


def build_component_b64(component_path: str | None) -> str | None:
    if not component_path:
        return None
    with open(component_path, "rb") as f:
        data = f.read()
    return b64url(data)


def build_attestation_request(
    tee: str,
    evidence_b64: str,
    component_id: str | None = None,
    component_path: str | None = None,
) -> dict:
    req = {"tee": tee, "evidence": evidence_b64}
    component_b64 = build_component_b64(component_path)
    if component_b64:
        req["verifier_component"] = component_b64
    if component_id and not component_b64:
        req["verifier_component_id"] = component_id
    return {"verification_requests": [req], "policy_ids": ["default"]}


def post_json(url: str, payload: dict, timeout: float = 60.0) -> tuple[int, bytes]:
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
    here = pathlib.Path(__file__).resolve()
    return here.parents[2]


def default_snp_evidence_path() -> str:
    return str(repo_root() / "attestation-service" / "tests" / "e2e" / "evidence.json")


def default_tdx_quote_path() -> str:
    return str(repo_root() / "tdx_quote2.bin")


def default_snp_report_path() -> str:
    return str(repo_root() / "snp_report_v3_real.bin")
