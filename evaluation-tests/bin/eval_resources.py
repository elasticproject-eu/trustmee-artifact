import argparse
import json
import statistics
import sys
import threading
import time

from eval_common import (
    build_attestation_request,
    build_snp_evidence,
    build_tdx_evidence,
    default_snp_evidence_path,
    default_tdx_quote_path,
    post_json,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Measure RSS and CPU usage for a PID.")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--samples", type=int, default=100)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--url", help="AS /attestation endpoint URL for load")
    p.add_argument("--tee", choices=["snp", "tdx"])
    p.add_argument("--component-id")
    p.add_argument("--component-path")
    p.add_argument("--evidence-json", default=default_snp_evidence_path())
    p.add_argument("--no-cert-chain", action="store_true")
    p.add_argument("--quote", default=default_tdx_quote_path())
    p.add_argument("--ccel")
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--load-interval", type=float, default=0.1)
    p.add_argument("--output")
    return p.parse_args()


def read_rss_kb(pid: int) -> int:
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                parts = line.split()
                return int(parts[1])
    return 0


def read_proc_jiffies(pid: int) -> int:
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
        fields = f.read().split()
    utime = int(fields[13])
    stime = int(fields[14])
    return utime + stime


def read_total_jiffies() -> int:
    with open("/proc/stat", "r", encoding="utf-8") as f:
        line = f.readline()
    parts = line.split()
    return sum(int(x) for x in parts[1:])


def load_worker(stop_event: threading.Event, url: str, request: dict, timeout: float, interval: float) -> None:
    while not stop_event.is_set():
        post_json(url, request, timeout=timeout)
        if interval > 0:
            time.sleep(interval)


def main() -> int:
    args = parse_args()
    if args.component_id and args.component_path:
        raise SystemExit("Use only one of --component-id or --component-path.")
    if args.url and not args.tee:
        raise SystemExit("--tee is required when --url is set.")

    request = None
    if args.url:
        if args.tee == "snp":
            evidence_b64 = build_snp_evidence(args.evidence_json, not args.no_cert_chain)
        else:
            evidence_b64 = build_tdx_evidence(args.quote, args.ccel)
        request = build_attestation_request(
            args.tee, evidence_b64, args.component_id, args.component_path
        )

    stop_event = threading.Event()
    thread = None
    if args.url:
        thread = threading.Thread(
            target=load_worker,
            args=(stop_event, args.url, request, args.timeout, args.load_interval),
            daemon=True,
        )
        thread.start()

    rss_samples = []
    cpu_samples = []
    prev_proc = read_proc_jiffies(args.pid)
    prev_total = read_total_jiffies()
    for _ in range(args.samples):
        time.sleep(args.interval)
        proc = read_proc_jiffies(args.pid)
        total = read_total_jiffies()
        cpu_pct = 0.0
        if total > prev_total:
            cpu_pct = (proc - prev_proc) / (total - prev_total) * 100.0
        rss_kb = read_rss_kb(args.pid)
        rss_samples.append(rss_kb)
        cpu_samples.append(cpu_pct)
        prev_proc = proc
        prev_total = total

    stop_event.set()
    if thread:
        thread.join(timeout=5)

    result = {
        "rss_kb": {
            "mean": statistics.mean(rss_samples) if rss_samples else 0.0,
            "std": statistics.pstdev(rss_samples) if len(rss_samples) > 1 else 0.0,
        },
        "cpu_pct": {
            "mean": statistics.mean(cpu_samples) if cpu_samples else 0.0,
            "std": statistics.pstdev(cpu_samples) if len(cpu_samples) > 1 else 0.0,
        },
    }
    payload = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
