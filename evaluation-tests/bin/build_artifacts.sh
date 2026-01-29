#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "== build restful-as =="
native_openssl_env=()
if [[ -n "${NATIVE_OPENSSL_DIR:-}" ]]; then
  native_openssl_env=(OPENSSL_DIR="${NATIVE_OPENSSL_DIR}" OPENSSL_NO_PKG_CONFIG=1 OPENSSL_STATIC=1)
  if [[ -z "${OPENSSL_NO_VENDOR:-}" ]]; then
    native_openssl_env+=(OPENSSL_NO_VENDOR=1)
  fi
fi

env "${native_openssl_env[@]}" cargo build -p attestation-service \
  --no-default-features \
  --features "restful-bin,snp-verifier,tdx-verifier" \
  --bin restful-as \
  --release

if command -v rustup >/dev/null 2>&1; then
  if ! rustup target list --installed | grep -q "wasm32-wasip2"; then
    echo "missing wasm32-wasip2 target; install with: rustup target add wasm32-wasip2" >&2
    exit 2
  fi
fi

echo "== build tdx verifier component =="
cargo build -p tdx-verifier-component --release --target wasm32-wasip2

if [[ "${SKIP_SNP_WASM:-}" == "1" ]]; then
  echo "SKIP_SNP_WASM=1 set; skipping SNP Wasm component build" >&2
  exit 0
fi

if [[ -z "${OPENSSL_DIR:-}" ]]; then
  echo "OPENSSL_DIR is required to build snp-verifier-component for Wasm" >&2
  echo "set OPENSSL_DIR and re-run (or set SKIP_SNP_WASM=1)" >&2
  exit 2
fi

echo "== build snp verifier component =="
env -u OPENSSL_NO_PKG_CONFIG CFLAGS= CXXFLAGS= \
  RUSTFLAGS='-C target-feature=+simd128' \
  OPENSSL_DIR="${OPENSSL_DIR}" \
  OPENSSL_STATIC=1 \
  cargo build -p snp-verifier-component --release --target wasm32-wasip2
