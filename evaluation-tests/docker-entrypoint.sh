#!/usr/bin/env bash
set -euo pipefail

: "${OPENSSL_DIR:=/opt/openssl/out/openssl-wasip2-simd}"
: "${NATIVE_OPENSSL_DIR:=/opt/openssl/out/openssl-native}"
: "${OPENSSL_STATIC:=0}"
: "${WASM_SIGNATURE_ENFORCE:=1}"

export OPENSSL_DIR
export NATIVE_OPENSSL_DIR
export OPENSSL_STATIC
export WASM_SIGNATURE_ENFORCE

exec bash /work/evaluation-tests/run_all.sh
