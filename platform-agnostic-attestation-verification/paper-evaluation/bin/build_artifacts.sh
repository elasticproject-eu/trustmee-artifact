#!/usr/bin/env bash
# Build all artifacts the paper-evaluation needs:
#   1. `restful-as` with snp-verifier, tdx-verifier, sgx-verifier,
#      dcap-qvl native variants, and the wasm-verification-component driver enabled.
#   2. SNP wasm verifier component (default + host-crypto variants).
#   3. TDX + SGX wasm verifier components (modified to consume CMW collateral).
#   4. `attestation-input-for-trustmee` CLI (builds CMW request bodies).
#   5. `fetch-tdx-collateral` helper (pre-fetches Intel collateral for CMW).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

echo "== build restful-as =="
native_env=()
if [[ -n "${NATIVE_OPENSSL_DIR:-}" ]]; then
  native_env=(
    OPENSSL_DIR="$NATIVE_OPENSSL_DIR"
    OPENSSL_NO_PKG_CONFIG=1
    OPENSSL_STATIC="${OPENSSL_STATIC:-1}"
  )
  if [[ -z "${OPENSSL_NO_VENDOR:-}" ]]; then
    native_env+=(OPENSSL_NO_VENDOR=1)
  fi
fi

(
  cd "$REPO_ROOT"
  env "${native_env[@]}" cargo build -p attestation-service \
    --no-default-features \
    --features "restful-bin,snp-verifier,tdx-verifier,tdx-verifier-dcap-qvl,sgx-verifier,sgx-verifier-dcap-qvl,wasm-verification-component-driver" \
    --bin restful-as \
    --release
)

if ! (cd "$REPO_ROOT" && rustup target list --installed 2>/dev/null | grep -q wasm32-wasip2); then
  echo "installing wasm32-wasip2 target" >&2
  rustup target add wasm32-wasip2
fi

echo "== build TDX wasm component =="
(
  cd "$WORKSPACE_ROOT/wasm-verification-components"
  cargo build -p tdx-verifier-component --release --target wasm32-wasip2
)

echo "== build SGX wasm component =="
(
  cd "$WORKSPACE_ROOT/wasm-verification-components"
  cargo build -p sgx-verifier-component --release --target wasm32-wasip2
)

if [[ "${SKIP_SNP_WASM:-}" != "1" ]]; then
  if [[ -z "${OPENSSL_DIR:-}" ]]; then
    echo "OPENSSL_DIR is required to build the SNP wasm components" >&2
    echo "(set OPENSSL_DIR and re-run, or set SKIP_SNP_WASM=1 to skip)" >&2
    exit 2
  fi
  echo "== build SNP wasm component (wasm crypto) =="
  (
    cd "$WORKSPACE_ROOT/wasm-verification-components"
    env -u OPENSSL_NO_PKG_CONFIG CFLAGS= CXXFLAGS= \
      RUSTFLAGS='-C target-feature=+simd128' \
      OPENSSL_DIR="$OPENSSL_DIR" \
      OPENSSL_STATIC=1 \
      cargo build -p snp-verifier-component --release --target wasm32-wasip2
  )

  echo "== build SNP wasm component (host crypto) =="
  (
    cd "$WORKSPACE_ROOT/wasm-verification-components"
    env -u OPENSSL_NO_PKG_CONFIG CFLAGS= CXXFLAGS= \
      RUSTFLAGS='-C target-feature=+simd128' \
      OPENSSL_DIR="$OPENSSL_DIR" \
      OPENSSL_STATIC=1 \
      cargo build -p snp-verifier-host-crypto-component --release --target wasm32-wasip2
  )
fi

echo "== build attestation-input-for-trustmee CLI =="
(
  cd "$WORKSPACE_ROOT/attestation-input-for-trustmee"
  cargo build --release --bin attestation-input-format
)

echo "== build fetch-tdx-collateral helper =="
(
  cd "$REPO_ROOT/paper-evaluation/tools/fetch-tdx-collateral"
  env "${native_env[@]}" cargo build --release
)

echo "== build wasmtime-compile-bench helper =="
(
  cd "$REPO_ROOT/paper-evaluation/tools/wasmtime-compile-bench"
  env "${native_env[@]}" cargo build --release
)

echo "== done =="
echo "  restful-as:                $REPO_ROOT/target/release/restful-as"
echo "  attestation-input-format:  $WORKSPACE_ROOT/attestation-input-for-trustmee/target/release/attestation-input-format"
echo "  fetch-tdx-collateral:      $REPO_ROOT/paper-evaluation/tools/fetch-tdx-collateral/target/release/fetch-tdx-collateral"
echo "  wasmtime-compile-bench:    $REPO_ROOT/paper-evaluation/tools/wasmtime-compile-bench/target/release/wasmtime-compile-bench"
echo "  SNP wasm:                  $WORKSPACE_ROOT/wasm-verification-components/target/wasm32-wasip2/release/snp_verifier_component.wasm"
echo "  SNP host-crypto wasm:      $WORKSPACE_ROOT/wasm-verification-components/target/wasm32-wasip2/release/snp_verifier_host_crypto_component.wasm"
echo "  SGX wasm:                  $WORKSPACE_ROOT/wasm-verification-components/target/wasm32-wasip2/release/sgx_verifier_component.wasm"
echo "  TDX wasm:                  $WORKSPACE_ROOT/wasm-verification-components/target/wasm32-wasip2/release/tdx_verifier_component.wasm"
