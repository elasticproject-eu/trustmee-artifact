#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="${TMP_DIR:-$REPO_ROOT/paper-evaluation/tmp}"
PID_PATH="${PID_PATH:-$TMP_DIR/restful-as.pid}"

if [[ ! -f "$PID_PATH" ]]; then
  exit 0
fi

PID="$(cat "$PID_PATH")"
if [[ -z "$PID" ]]; then
  rm -f "$PID_PATH"
  exit 0
fi

process_alive() {
  kill -0 "$PID" 2>/dev/null || return 1

  if [[ -r "/proc/$PID/stat" ]]; then
    local state
    state="$(awk '{print $3}' "/proc/$PID/stat" 2>/dev/null || true)"
    [[ "$state" != "Z" ]]
    return
  fi

  return 0
}

if process_alive; then
  kill "$PID" 2>/dev/null || true
  for _ in $(seq 1 200); do
    if ! process_alive; then
      break
    fi
    sleep 0.05
  done
  if process_alive; then
    kill -9 "$PID" 2>/dev/null || true
    for _ in $(seq 1 100); do
      if ! process_alive; then
        break
      fi
      sleep 0.05
    done
  fi
fi
rm -f "$PID_PATH"
