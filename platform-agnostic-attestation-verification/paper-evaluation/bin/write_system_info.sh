#!/usr/bin/env bash
# Write a system_info.txt snapshot that documents the host the eval ran on.
set -euo pipefail

OUT="${1:?usage: $0 <output-path>}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

{
  echo "timestamp: $(date +%Y-%m-%dT%H:%M:%S%z)"
  echo "hostname: $(hostname)"
  echo "kernel: $(uname -a)"
  echo
  echo "os_release:"
  if [[ -f /etc/os-release ]]; then
    cat /etc/os-release
  else
    echo "(missing /etc/os-release)"
  fi

  wasmtime_version=""
  if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
    wasmtime_version="$(
      awk '
        $1 == "name" && $3 == "\"wasmtime\"" { in_pkg = 1; next }
        in_pkg && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
        in_pkg && $1 == "name" { in_pkg = 0 }
      ' "$REPO_ROOT/Cargo.lock"
    )"
  fi
  if [[ -n "$wasmtime_version" ]]; then
    echo
    echo "wasmtime:"
    echo "version: $wasmtime_version"
  fi

  echo
  echo "rust_toolchain:"
  rustc --version 2>/dev/null || echo "(rustc not found)"
  cargo --version 2>/dev/null || echo "(cargo not found)"

  echo
  echo "cpu:"
  if command -v lscpu >/dev/null 2>&1; then
    lscpu
  elif [[ -f /proc/cpuinfo ]]; then
    cat /proc/cpuinfo
  else
    echo "(cpu info not available)"
  fi

  echo
  echo "memory:"
  if command -v free >/dev/null 2>&1; then
    free -h
  elif [[ -f /proc/meminfo ]]; then
    cat /proc/meminfo
  else
    echo "(memory info not available)"
  fi
} > "$OUT"
