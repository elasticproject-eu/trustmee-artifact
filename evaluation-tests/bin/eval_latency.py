import argparse
import json
import statistics
import sys
import time

from eval_common import (
    build_attestation_request,
    build_snp_evidence,
    build_tdx_evidence,
    default_snp_evidence_path,
    default_tdx_quote_path,
    post_json,
)


def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="backslashreplace")


def init_result_log(path: str | None, payload: dict) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n")


def append_result_log(path: str | None, payload: dict) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Measure attestation request latency.")
    p.add_argument("--url", required=True, help="AS /attestation endpoint URL")
    p.add_argument("--tee", choices=["snp", "tdx"], required=True)
    p.add_argument("--runs", type=int, default=100)
    p.add_argument("--warmup", type=int, default=0)
    p.add_argument("--component-id")
    p.add_argument("--component-path")
    p.add_argument("--evidence-json", default=default_snp_evidence_path())
    p.add_argument("--no-cert-chain", action="store_true")
    p.add_argument("--quote", default=default_tdx_quote_path())
    p.add_argument("--ccel")
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--interval", type=float, default=0.0)
    p.add_argument("--max-retries", type=int, default=0)
    p.add_argument("--retry-initial", type=float, default=1.0)
    p.add_argument("--retry-backoff", type=float, default=2.0)
    p.add_argument("--dump-request")
    p.add_argument("--output")
    p.add_argument("--result-log", help="Append attestation responses to a JSONL log.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.component_id and args.component_path:
        raise SystemExit("Use only one of --component-id or --component-path.")

    if args.tee == "snp":
        evidence_b64 = build_snp_evidence(args.evidence_json, not args.no_cert_chain)
    else:
        evidence_b64 = build_tdx_evidence(args.quote, args.ccel)

    request = build_attestation_request(
        args.tee, evidence_b64, args.component_id, args.component_path
    )
    if args.dump_request:
        payload = json.dumps(request, separators=(",", ":"))
        with open(args.dump_request, "w", encoding="utf-8") as f:
            f.write(payload + "\n")

    init_result_log(
        args.result_log,
        {
            "event": "start",
            "timestamp": time.time(),
            "url": args.url,
            "tee": args.tee,
            "runs": args.runs,
            "warmup": args.warmup,
            "component_id": args.component_id,
            "component_path": args.component_path,
            "no_cert_chain": args.no_cert_chain,
            "evidence_json": args.evidence_json,
            "quote": args.quote,
            "ccel": args.ccel,
            "timeout": args.timeout,
            "interval": args.interval,
            "max_retries": args.max_retries,
            "retry_initial": args.retry_initial,
            "retry_backoff": args.retry_backoff,
        },
    )

    for _ in range(args.warmup):
        status, _ = post_json(args.url, request, timeout=args.timeout)
        if status < 200 or status >= 300:
            raise RuntimeError(f"warmup failed with status {status}")

    samples = []
    ok_runs = 0
    for idx in range(args.runs):
        attempt = 0
        delay = args.retry_initial
        attempt_errors = []
        while True:
            try:
                t0 = time.perf_counter()
                status, response = post_json(args.url, request, timeout=args.timeout)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                response_text = safe_decode(response)
            except Exception as exc:
                attempt += 1
                attempt_errors.append(
                    {"attempt": attempt, "error": "exception", "detail": str(exc)}
                )
                if attempt > args.max_retries:
                    append_result_log(
                        args.result_log,
                        {
                            "event": "attestation",
                            "run": idx + 1,
                            "ok": False,
                            "attempts": attempt,
                            "error": "exception",
                            "detail": str(exc),
                            "errors": attempt_errors,
                        },
                    )
                    raise RuntimeError(f"request failed with exception: {exc}") from exc
                time.sleep(max(0.0, delay))
                delay *= max(1.0, args.retry_backoff)
                continue
            if 200 <= status < 300:
                samples.append(elapsed_ms)
                ok_runs += 1
                append_result_log(
                    args.result_log,
                    {
                        "event": "attestation",
                        "run": idx + 1,
                        "ok": True,
                        "status": status,
                        "elapsed_ms": elapsed_ms,
                        "attempts": attempt + 1,
                        "response": response_text,
                        "errors": attempt_errors,
                    },
                )
                break
            attempt += 1
            attempt_errors.append(
                {
                    "attempt": attempt,
                    "error": "http_status",
                    "status": status,
                    "response": response_text,
                }
            )
            if attempt > args.max_retries:
                append_result_log(
                    args.result_log,
                    {
                        "event": "attestation",
                        "run": idx + 1,
                        "ok": False,
                        "status": status,
                        "attempts": attempt,
                        "response": response_text,
                        "errors": attempt_errors,
                    },
                )
                raise RuntimeError(f"request failed with status {status}")
            time.sleep(max(0.0, delay))
            delay *= max(1.0, args.retry_backoff)
        if args.interval > 0 and idx + 1 < args.runs:
            time.sleep(args.interval)

    mean_ms = statistics.mean(samples) if samples else 0.0
    std_ms = statistics.pstdev(samples) if len(samples) > 1 else 0.0

    result = {
        "runs": len(samples),
        "mean_ms": mean_ms,
        "std_ms": std_ms,
        "min_ms": min(samples) if samples else 0.0,
        "max_ms": max(samples) if samples else 0.0,
    }
    payload = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
    append_result_log(
        args.result_log,
        {
            "event": "summary",
            "timestamp": time.time(),
            "runs": len(samples),
            "ok_runs": ok_runs,
            "mean_ms": mean_ms,
            "std_ms": std_ms,
            "min_ms": min(samples) if samples else 0.0,
            "max_ms": max(samples) if samples else 0.0,
        },
    )
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
