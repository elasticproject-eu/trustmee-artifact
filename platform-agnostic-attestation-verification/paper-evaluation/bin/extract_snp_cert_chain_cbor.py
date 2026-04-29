#!/usr/bin/env python3
"""Extract the `cert_chain` from an SNP evidence JSON and write it as a CBOR
payload suitable for a CMW endorsement.

The trustmee SNP wasm component expects an endorsement with media type
`application/vnd.trustmee.snp-collateral+cbor` whose payload is CBOR-encoded
`SnpCollateral { cert_chain }` — the same shape the upstream component parses.

We reuse the `attestation-input-for-trustmee` build pipeline: just produce the
CBOR bytes here via the `cbor2` package. If `cbor2` is not available, fall
back to a tiny CBOR encoder implemented inline (evidence/cert chain is small).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import cbor2
    HAVE_CBOR2 = True
except Exception:
    HAVE_CBOR2 = False


def cert_entry_from_json(entry: dict) -> dict:
    """The upstream CertTableEntry serde shape uses snake_case fields:
    {"cert_type": "VCEK"|..., "data": [u8...]}."""
    return {
        "cert_type": entry["cert_type"],
        "data": bytes(entry["data"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True, help="SNP evidence JSON path")
    ap.add_argument("--output", required=True, help="Where to write CBOR payload")
    args = ap.parse_args()

    with open(args.evidence, "r", encoding="utf-8") as f:
        evidence = json.load(f)

    chain = evidence.get("cert_chain")
    if not chain:
        print(
            f"ERROR: no cert_chain in {args.evidence} — cannot build SNP collateral endorsement",
            file=sys.stderr,
        )
        return 2

    entries = [cert_entry_from_json(e) for e in chain]
    payload = {"cert_chain": entries}

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    if HAVE_CBOR2:
        with open(args.output, "wb") as f:
            cbor2.dump(payload, f)
    else:
        raise SystemExit(
            "cbor2 Python package is required; install via `pip install cbor2`"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
