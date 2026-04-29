#!/usr/bin/env bash
# Entrypoint run inside the paper-evaluation docker image.
set -euo pipefail

: "${OPENSSL_DIR:=/opt/openssl/out/openssl-wasip2-simd}"
: "${NATIVE_OPENSSL_DIR:=/opt/openssl/out/openssl-native}"
: "${OPENSSL_STATIC:=0}"

export OPENSSL_DIR NATIVE_OPENSSL_DIR OPENSSL_STATIC

exec bash /work/platform-agnostic-attestation-verification/paper-evaluation/run_all.sh
