import argparse
import json
import sys

from eval_common import build_component_b64, post_json


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Register a Wasm component verifier.")
    p.add_argument("--url", required=True, help="AS /component endpoint URL")
    p.add_argument("--component", required=True)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    component_b64 = build_component_b64(args.component)
    payload = {"verifier_component": component_b64}
    status, body = post_json(args.url, payload, timeout=120.0)
    if status < 200 or status >= 300:
        raise RuntimeError(f"registration failed with status {status}")
    data = json.loads(body.decode("utf-8"))
    print(data["component_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
