#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
if [[ -z "$MODE" ]]; then
  echo "usage: $0 <native|wasm>" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="${TMP_DIR:-$ROOT_DIR/evaluation-tests/tmp}"
PID_PATH="${PID_PATH:-$TMP_DIR/restful-as-${MODE}.pid}"

if [[ ! -f "$PID_PATH" ]]; then
  echo "pid file not found: $PID_PATH" >&2
  exit 0
fi

PID="$(cat "$PID_PATH")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID" >/dev/null 2>&1 || true
  for _ in $(seq 1 200); do
    if ! kill -0 "$PID" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if kill -0 "$PID" 2>/dev/null; then
    kill -9 "$PID" >/dev/null 2>&1 || true
  fi
fi
rm -f "$PID_PATH"
