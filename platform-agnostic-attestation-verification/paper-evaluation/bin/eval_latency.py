#!/usr/bin/env python3
"""POST a pre-built REST attestation body N times and record per-request latency.

Writes:
  - a JSON summary ({runs, mean_ms, std_ms, min_ms, max_ms}) to --output
  - optional JSONL result log (--result-log) with one event per request for
    later cross-referencing with AS-side timing events.
  - optional JSON attestation result log (--attestation-result-log) containing
    the response body returned by the first measured request after warmup.
"""

from __future__ import annotations

import argparse
import base64
import json
import statistics
import sys
import time
from pathlib import Path

from eval_common import post_json


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="AS /attestation endpoint")
    ap.add_argument("--body-file", required=True, help="Path to pre-built REST body JSON")
    ap.add_argument(
        "--warmup-body-file",
        help="Optional request body used only for warmup requests",
    )
    ap.add_argument("--runs", type=int, default=50)
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--interval", type=float, default=0.0, help="Sleep between requests (s)")
    ap.add_argument("--max-retries", type=int, default=0)
    ap.add_argument("--retry-initial", type=float, default=1.0)
    ap.add_argument("--retry-backoff", type=float, default=2.0)
    ap.add_argument("--output", required=True, help="Path for summary JSON")
    ap.add_argument("--result-log", help="Optional JSONL log of per-request events")
    ap.add_argument(
        "--attestation-result-log",
        help=(
            "Optional JSON log with the attestation result returned by the first "
            "measured request, after warmup requests have completed"
        ),
    )
    return ap.parse_args()


def attempt_once(
    url: str, body: dict, timeout: float
) -> tuple[float, int, bytes]:
    t0 = time.perf_counter()
    status, resp = post_json(url, body, timeout=timeout)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    return dt_ms, status, resp


def run_once_with_retries(
    url: str,
    body: dict,
    *,
    timeout: float,
    max_retries: int,
    initial_backoff: float,
    backoff: float,
) -> tuple[float, int, bytes, int]:
    """Return (elapsed_ms, status, response, attempts)."""
    delay = initial_backoff
    for attempt in range(max_retries + 1):
        try:
            dt_ms, status, resp = attempt_once(url, body, timeout)
            if status == 200:
                return dt_ms, status, resp, attempt + 1
            if attempt == max_retries:
                return dt_ms, status, resp, attempt + 1
        except Exception as e:
            if attempt == max_retries:
                raise
            time.sleep(delay)
            delay *= backoff
            continue
        time.sleep(delay)
        delay *= backoff
    return 0.0, 0, b"", 0  # unreachable


def attestation_result_fields(resp: bytes) -> dict:
    try:
        result = resp.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        result = base64.b64encode(resp).decode("ascii")
        encoding = "base64"
    return {
        "attestation_result": result,
        "attestation_result_encoding": encoding,
        "attestation_result_bytes": len(resp),
    }


def write_attestation_result_log(path: str, record: dict) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")


def main() -> int:
    args = parse_args()
    with open(args.body_file, "r", encoding="utf-8") as f:
        body = json.load(f)
    warmup_body = body
    if args.warmup_body_file:
        with open(args.warmup_body_file, "r", encoding="utf-8") as f:
            warmup_body = json.load(f)

    result_log = None
    if args.result_log:
        result_log = open(args.result_log, "w", encoding="utf-8")
        start_record = {
            "event": "start",
            "runs": args.runs,
            "warmup": args.warmup,
            "url": args.url,
            "body_file": args.body_file,
            "warmup_body_file": args.warmup_body_file,
            "timestamp": time.time(),
        }
        result_log.write(json.dumps(start_record) + "\n")

    for _ in range(args.warmup):
        try:
            _, status, resp, _ = run_once_with_retries(
                args.url,
                warmup_body,
                timeout=args.timeout,
                max_retries=args.max_retries,
                initial_backoff=args.retry_initial,
                backoff=args.retry_backoff,
            )
            if args.warmup_body_file and status != 200:
                raise RuntimeError(
                    f"warmup failed with status={status} response={resp[:200]!r}"
                )
        except Exception as e:
            if args.warmup_body_file:
                raise
            print(f"warmup failed: {e}", file=sys.stderr)

    samples: list[float] = []
    errors: list[str] = []
    first_measured_result_logged = False
    for i in range(args.runs):
        try:
            dt_ms, status, resp, attempts = run_once_with_retries(
                args.url,
                body,
                timeout=args.timeout,
                max_retries=args.max_retries,
                initial_backoff=args.retry_initial,
                backoff=args.retry_backoff,
            )
            ok = status == 200
            if ok:
                samples.append(dt_ms)
            else:
                errors.append(
                    f"request {i}: status={status} response={resp[:200]!r}"
                )
            if result_log is not None:
                rec = {
                    "event": "attestation",
                    "i": i,
                    "ok": ok,
                    "elapsed_ms": dt_ms,
                    "status": status,
                    "attempts": attempts,
                }
                result_log.write(json.dumps(rec) + "\n")
            if args.attestation_result_log and not first_measured_result_logged:
                write_attestation_result_log(
                    args.attestation_result_log,
                    {
                        "event": "first_measured_attestation_result",
                        "request_index": i,
                        "warmup": args.warmup,
                        "ok": ok,
                        "elapsed_ms": dt_ms,
                        "status": status,
                        "attempts": attempts,
                        "url": args.url,
                        "body_file": args.body_file,
                        "warmup_body_file": args.warmup_body_file,
                        "timestamp": time.time(),
                        **attestation_result_fields(resp),
                    },
                )
                first_measured_result_logged = True
        except Exception as e:
            errors.append(f"request {i}: exception {e}")
            if result_log is not None:
                rec = {"event": "attestation", "i": i, "ok": False, "error": str(e)}
                result_log.write(json.dumps(rec) + "\n")
            if args.attestation_result_log and not first_measured_result_logged:
                write_attestation_result_log(
                    args.attestation_result_log,
                    {
                        "event": "first_measured_attestation_result",
                        "request_index": i,
                        "warmup": args.warmup,
                        "ok": False,
                        "error": str(e),
                        "url": args.url,
                        "body_file": args.body_file,
                        "warmup_body_file": args.warmup_body_file,
                        "timestamp": time.time(),
                    },
                )
                first_measured_result_logged = True
        if args.interval > 0 and i != args.runs - 1:
            time.sleep(args.interval)

    if not samples:
        summary = {
            "runs": 0,
            "mean_ms": 0.0,
            "std_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "errors": errors,
        }
    else:
        summary = {
            "runs": len(samples),
            "mean_ms": statistics.fmean(samples),
            "std_ms": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
            "min_ms": min(samples),
            "max_ms": max(samples),
        }
        if errors:
            summary["errors"] = errors

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    if result_log is not None:
        result_log.write(json.dumps({"event": "summary", **summary}) + "\n")
        result_log.close()

    if not samples:
        print(f"ERROR: no successful runs ({len(errors)} errors)", file=sys.stderr)
        for e in errors[:3]:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
