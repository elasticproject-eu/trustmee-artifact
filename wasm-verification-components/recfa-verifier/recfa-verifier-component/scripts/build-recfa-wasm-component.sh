#!/usr/bin/env bash
# Build (and optionally test) the ReCFA verification component.
#
#   ./build-recfa-wasm-component.sh              # build only
#   ./build-recfa-wasm-component.sh --test       # build + run the fixture suite
#   ./build-recfa-wasm-component.sh --parity     # + compare against upstream check
#
# Requires: rustup target wasm32-wasip2, and wasi-sdk (>= 24) located via
# WASI_SDK_PATH, $HOME/wasi-sdk, or /opt/wasi-sdk.
#
# For --parity you also need upstream ReCFA checked out, so the vendored verifier
# can be diffed and compared against the original:
#   RECFA_UPSTREAM=/path/to/ReCFA ./build-recfa-wasm-component.sh --parity

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
component_dir="$(cd "$here/.." && pwd)"
recfa_dir="$(cd "$component_dir/.." && pwd)"
ws_dir="$(cd "$recfa_dir/.." && pwd)"

do_test=0
do_parity=0
for arg in "$@"; do
  case "$arg" in
    --test) do_test=1 ;;
    --parity) do_parity=1; do_test=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# ---- locate wasi-sdk -------------------------------------------------------
if [[ -z "${WASI_SDK_PATH:-}" ]]; then
  for cand in "$HOME/wasi-sdk" /opt/wasi-sdk; do
    if [[ -x "$cand/bin/clang++" ]]; then WASI_SDK_PATH="$cand"; break; fi
  done
fi
if [[ -z "${WASI_SDK_PATH:-}" || ! -x "$WASI_SDK_PATH/bin/clang++" ]]; then
  echo "error: wasi-sdk not found. Set WASI_SDK_PATH to a wasi-sdk >= 24." >&2
  echo "  https://github.com/WebAssembly/wasi-sdk/releases" >&2
  exit 1
fi
export WASI_SDK_PATH
echo "==> wasi-sdk: $WASI_SDK_PATH"

# ---- build -----------------------------------------------------------------
echo "==> building recfa-verifier-component for wasm32-wasip2"
( cd "$ws_dir" && cargo build -p recfa-verifier-component --release --target wasm32-wasip2 )

target_dir="${CARGO_TARGET_DIR:-$ws_dir/target}"
wasm="$target_dir/wasm32-wasip2/release/recfa_verifier_component.wasm"
if [[ ! -f "$wasm" ]]; then
  echo "error: expected component at $wasm" >&2
  exit 1
fi
echo "==> built $wasm ($(stat -c%s "$wasm") bytes)"

if command -v wasm-tools >/dev/null 2>&1; then
  wasm-tools validate --features all "$wasm"
  echo "==> wasm-tools validate: OK"
  if ! wasm-tools component wit "$wasm" | grep -q 'export trustee:verifier/verifier-interface'; then
    echo "error: component does not export trustee:verifier/verifier-interface" >&2
    exit 1
  fi
  echo "==> exports trustee:verifier/verifier-interface: OK"
fi

# ---- fixture suite ---------------------------------------------------------
if [[ "$do_test" == 1 ]]; then
  echo "==> building test harness"
  ( cd "$ws_dir" && cargo build -p recfa-verifier-test )
  harness="$target_dir/debug/recfa-verifier-test"

  echo "==> running fixture suite through the component"
  "$harness" \
    --component "$wasm" \
    --disassembly "$recfa_dir/test_data/prog.asm" \
    --cfg         "$recfa_dir/test_data/prog.dot" \
    --policy-f    "$recfa_dir/test_data/binfo.prog" \
    --batch       "$recfa_dir/test_data" \
    --compiler gcc

  echo "==> report-data binding must be enforced"
  "$harness" --component "$wasm" \
    --disassembly "$recfa_dir/test_data/prog.asm" \
    --cfg "$recfa_dir/test_data/prog.dot" \
    --policy-f "$recfa_dir/test_data/binfo.prog" \
    --trace "$recfa_dir/test_data/pass_simple.trace" \
    --bind-report-data --expect secure >/dev/null
  "$harness" --component "$wasm" \
    --disassembly "$recfa_dir/test_data/prog.asm" \
    --cfg "$recfa_dir/test_data/prog.dot" \
    --policy-f "$recfa_dir/test_data/binfo.prog" \
    --trace "$recfa_dir/test_data/pass_simple.trace" \
    --bind-wrong-report-data --expect failed >/dev/null
  echo "==> report-data binding: OK"
fi

# ---- parity against unmodified upstream ------------------------------------
if [[ "$do_parity" == 1 ]]; then
  if [[ -z "${RECFA_UPSTREAM:-}" ]]; then
    echo "warn: RECFA_UPSTREAM not set, skipping upstream parity" >&2
    exit 0
  fi
  upstream_src="$RECFA_UPSTREAM/src/verifier/check.cpp"
  [[ -f "$upstream_src" ]] || { echo "error: no $upstream_src" >&2; exit 1; }

  echo "==> regenerating vendor/check.cpp from upstream and diffing"
  ( cd "$component_dir/vendor" && python3 patch-upstream.py "$upstream_src" )
  if ! git -C "$ws_dir" diff --quiet -- "$component_dir/vendor/check.cpp" 2>/dev/null; then
    echo "note: vendor/check.cpp changed relative to the committed copy" >&2
  fi

  echo "==> building upstream check and the vendored parity driver"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  c++ -O2 -std=gnu++14 -w -no-pie "$upstream_src" -o "$tmp/check_upstream"
  c++ -O2 -std=gnu++14 -w -I"$component_dir/vendor" \
      "$recfa_dir/tools/parity-driver.cpp" "$component_dir/vendor/check.cpp" \
      -o "$tmp/parity-driver"

  echo "==> comparing vendored verifier against unmodified upstream"
  python3 "$recfa_dir/tools/parity-check.py" \
    --oracle "$tmp/check_upstream" \
    --driver "$tmp/parity-driver" \
    --data   "$recfa_dir/test_data"
fi

echo "==> done"
