#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKSPACE_DIR="$ROOT_DIR"
OUT_DIR="$WORKSPACE_DIR/target/wasm32-wasip2/release"
OUT_WASM="$OUT_DIR/snp_verifier_host_crypto_component.wasm"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.90.0}"

echo "== ensuring wasm32-wasip2 target =="
rustup target add wasm32-wasip2 --toolchain "$RUSTUP_TOOLCHAIN"

echo "== building snp-verifier-host-crypto-component =="
cargo build \
  --manifest-path "$WORKSPACE_DIR/Cargo.toml" \
  -p snp-verifier-host-crypto-component \
  --release \
  --target wasm32-wasip2

echo "done: $OUT_WASM"
