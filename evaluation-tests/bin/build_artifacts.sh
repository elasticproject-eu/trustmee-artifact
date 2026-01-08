#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "== build restful-as =="
cargo build -p attestation-service \
  --no-default-features \
  --features "restful-bin,snp-verifier,tdx-verifier" \
  --bin restful-as \
  --release

if ! cargo component --version >/dev/null 2>&1; then
  echo "cargo-component is required (cargo component ...)" >&2
  echo "install with: cargo install cargo-component" >&2
  exit 2
fi

if command -v rustup >/dev/null 2>&1; then
  if ! rustup target list --installed | grep -q "wasm32-wasip1"; then
    echo "missing wasm32-wasip1 target; install with: rustup target add wasm32-wasip1" >&2
    exit 2
  fi
fi

echo "== build tdx verifier component =="
cargo component build -p tdx-verifier-component --release --target wasm32-wasip1

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
  cargo component build -p snp-verifier-component --release --target wasm32-wasip1
