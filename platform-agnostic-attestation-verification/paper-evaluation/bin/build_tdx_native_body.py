#!/usr/bin/env python3
"""Write a native-TDX REST body JSON to --output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval_common import build_tdx_native_body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quote", required=True)
    ap.add_argument("--ccel")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    body = build_tdx_native_body(args.quote, args.ccel)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(body, f)
        f.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
