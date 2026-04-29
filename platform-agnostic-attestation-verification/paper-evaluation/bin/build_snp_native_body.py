#!/usr/bin/env python3
"""Write a native-SNP REST body JSON to --output.

Used for eval 1 (cert_chain included to skip KDS) and eval 7 (cert_chain
stripped so the verifier must hit KDS).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval_common import build_snp_native_body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--no-cert-chain", action="store_true")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    body = build_snp_native_body(args.evidence, include_cert_chain=not args.no_cert_chain)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(body, f)
        f.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
