#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TARGET="${TARGET:-wasm32-wasip2}"
PROFILE="${PROFILE:-release}"
if [[ "$PROFILE" == "release" ]]; then
  PROFILE_FLAG="--release"
elif [[ "$PROFILE" == "debug" ]]; then
  PROFILE_FLAG=""
else
  echo "unsupported PROFILE=$PROFILE (use release or debug)" >&2
  exit 1
fi

BOOTLOADER_PKG="bootloader-verifier-component"
TDX_PKG="tdx-verifier-component"

BOOTLOADER_COMPONENT="$ROOT_DIR/target/$TARGET/$PROFILE/bootloader_verifier_component.wasm"
TDX_COMPONENT="$ROOT_DIR/target/$TARGET/$PROFILE/tdx_verifier_component.wasm"
COMPOSED_COMPONENT="$ROOT_DIR/target/$TARGET/$PROFILE/bootloader_tdx_verifier_component.wasm"
BOOTLOADER_COMPONENT_COMPOSE="$ROOT_DIR/target/$TARGET/$PROFILE/bootloader-verifier-component.wasm"
TDX_COMPONENT_COMPOSE="$ROOT_DIR/target/$TARGET/$PROFILE/tdx-verifier-component.wasm"

echo "== building $TDX_PKG =="
cargo build \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  -p "$TDX_PKG" \
  --target "$TARGET" \
  $PROFILE_FLAG

echo "== building $BOOTLOADER_PKG =="
cargo build \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  -p "$BOOTLOADER_PKG" \
  --target "$TARGET" \
  $PROFILE_FLAG

if [[ ! -f "$BOOTLOADER_COMPONENT" ]]; then
  echo "missing bootloader component: $BOOTLOADER_COMPONENT" >&2
  exit 1
fi

if [[ ! -f "$TDX_COMPONENT" ]]; then
  echo "missing tdx component: $TDX_COMPONENT" >&2
  exit 1
fi

echo "== composing bootloader + tdx =="
cp "$BOOTLOADER_COMPONENT" "$BOOTLOADER_COMPONENT_COMPOSE"
cp "$TDX_COMPONENT" "$TDX_COMPONENT_COMPOSE"
if ! command -v wac >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: `wac` is required for component composition.
install: cargo install wac-cli
EOF
  exit 1
fi

wac plug \
  "$BOOTLOADER_COMPONENT_COMPOSE" \
  --plug "$TDX_COMPONENT_COMPOSE" \
  -o "$COMPOSED_COMPONENT"

echo "done: $COMPOSED_COMPONENT"
