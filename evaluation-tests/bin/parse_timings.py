import argparse
import json
import statistics
import sys


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Parse JSON timing lines from logs.")
    p.add_argument("--log", required=True)
    p.add_argument("--event", required=True)
    p.add_argument("--tee")
    p.add_argument("--mode")
    p.add_argument("--fields", nargs="*")
    p.add_argument("--output")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    fields = args.fields
    if not fields:
        if args.event == "as_verifier_timing":
            fields = ["ms"]
        elif args.event == "snp_step_timing":
            fields = ["cert_chain_ms", "signature_ms", "others_ms", "total_ms"]
        else:
            raise SystemExit("Use --fields for unknown event type.")

    values = {name: [] for name in fields}
    with open(args.log, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") != args.event:
                continue
            if args.tee and record.get("tee") != args.tee:
                continue
            if args.mode and record.get("mode") != args.mode:
                continue
            for name in fields:
                if name in record:
                    values[name].append(float(record[name]))

    out = {}
    for name, samples in values.items():
        out[name] = {
            "mean": statistics.mean(samples) if samples else 0.0,
            "std": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
            "count": len(samples),
        }

    payload = json.dumps(out, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
