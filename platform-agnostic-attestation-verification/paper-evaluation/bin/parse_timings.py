#!/usr/bin/env python3
"""Extract JSON-line timing events emitted by the AS / verifier code.

The AS is launched with env vars that make specific code paths emit single-line
JSON events to stderr. This script reads the stderr log, filters by event name
(and optionally by `tee` / `mode`), and writes a summary JSON with mean/std for
each numeric field.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any


DEFAULT_FIELDS = {
    "as_verifier_timing": ["ms"],
    "as_tdx_collateral_timing": ["ms"],
    "snp_step_timing": ["cert_chain_ms", "signature_ms", "others_ms", "total_ms"],
    "wvc_load_timing": ["ms"],
    "wvc_instantiate_timing": ["ms"],
    "wvc_verify_timing": ["ms"],
    "wvc_total_timing": ["ms"],
}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True, help="AS stderr log path")
    ap.add_argument("--event", required=True, help="Event name to filter by")
    ap.add_argument("--tee", help="Filter by `tee` field (e.g. Snp, Tdx)")
    ap.add_argument(
        "--mode", help="Filter by `mode` field (e.g. native, wasm, native_dcap_qvl)"
    )
    ap.add_argument(
        "--fields",
        nargs="*",
        help="Numeric fields to aggregate. Defaults depend on --event.",
    )
    ap.add_argument(
        "--skip", type=int, default=0,
        help="Skip the first N matching records (e.g. a warmup run).",
    )
    ap.add_argument("--output", required=True, help="Summary JSON output")
    return ap.parse_args()


def parse_line(line: str) -> dict | None:
    s = line.strip()
    if not s:
        return None
    try:
        rec = json.loads(s)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict):
        return None
    return rec


def main() -> int:
    args = parse_args()
    fields = args.fields or DEFAULT_FIELDS.get(args.event, ["ms"])

    collected: dict[str, list[float]] = {f: [] for f in fields}
    total_matches = 0
    with open(args.log, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_line(line)
            if rec is None:
                continue
            if rec.get("event") != args.event:
                continue
            if args.tee and rec.get("tee") != args.tee:
                continue
            if args.mode and rec.get("mode") != args.mode:
                continue
            total_matches += 1
            if total_matches <= args.skip:
                continue
            for field in fields:
                v = rec.get(field)
                if isinstance(v, (int, float)):
                    collected[field].append(float(v))

    summary: dict[str, Any] = {"event": args.event, "matched": total_matches}
    if args.tee:
        summary["tee"] = args.tee
    if args.mode:
        summary["mode"] = args.mode
    if args.skip:
        summary["skipped"] = args.skip

    for field, values in collected.items():
        if not values:
            summary[field] = {"count": 0, "mean": 0.0, "std": 0.0}
        else:
            summary[field] = {
                "count": len(values),
                "mean": statistics.fmean(values),
                "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
                "min": min(values),
                "max": max(values),
            }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
