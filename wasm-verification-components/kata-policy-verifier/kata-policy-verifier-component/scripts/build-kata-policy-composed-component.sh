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

# Lower layer to plug into the kata-policy verifier:
#   stub (default) - fixture testing without a live TEE
#   tdx / snp      - real hardware verifiers
LOWER="${LOWER:-stub}"
case "$LOWER" in
  stub)
    LOWER_PKG="stub-hardware-verifier-component"
    LOWER_WASM="stub_hardware_verifier_component.wasm"
    COMPOSED_WASM="kata_policy_stub_verifier_component.wasm"
    ;;
  tdx)
    LOWER_PKG="tdx-verifier-component"
    LOWER_WASM="tdx_verifier_component.wasm"
    COMPOSED_WASM="kata_policy_tdx_verifier_component.wasm"
    ;;
  snp)
    LOWER_PKG="snp-verifier-component"
    LOWER_WASM="snp_verifier_component.wasm"
    COMPOSED_WASM="kata_policy_snp_verifier_component.wasm"
    ;;
  *)
    echo "unsupported LOWER=$LOWER (use stub, tdx or snp)" >&2
    exit 1
    ;;
esac

KATA_PKG="kata-policy-verifier-component"
KATA_COMPONENT="$ROOT_DIR/target/$TARGET/$PROFILE/kata_policy_verifier_component.wasm"
LOWER_COMPONENT="$ROOT_DIR/target/$TARGET/$PROFILE/$LOWER_WASM"
COMPOSED_COMPONENT="$ROOT_DIR/target/$TARGET/$PROFILE/$COMPOSED_WASM"

echo "== building $LOWER_PKG =="
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p "$LOWER_PKG" --target "$TARGET" $PROFILE_FLAG

echo "== building $KATA_PKG =="
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p "$KATA_PKG" --target "$TARGET" $PROFILE_FLAG

for f in "$KATA_COMPONENT" "$LOWER_COMPONENT"; do
  [[ -f "$f" ]] || { echo "missing component: $f" >&2; exit 1; }
done

if ! command -v wac >/dev/null 2>&1; then
  echo "error: \`wac\` is required for component composition. install: cargo install wac-cli" >&2
  exit 1
fi

echo "== composing kata-policy + $LOWER =="
wac plug "$KATA_COMPONENT" --plug "$LOWER_COMPONENT" -o "$COMPOSED_COMPONENT"

echo "done: $COMPOSED_COMPONENT"
