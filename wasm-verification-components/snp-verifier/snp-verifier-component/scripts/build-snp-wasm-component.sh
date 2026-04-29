#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-trustee-snp-wasm-builder}"
SNP_COMPONENT_REL="snp-verifier/snp-verifier-component"
if [[ ! -d "$ROOT_DIR/$SNP_COMPONENT_REL" ]]; then
  echo "snp-verifier-component directory not found under repo root: $ROOT_DIR" >&2
  exit 1
fi

DOCKERFILE_PATH="${DOCKERFILE_PATH:-$ROOT_DIR/$SNP_COMPONENT_REL/docker/Dockerfile.snp-wasm}"

echo "== building SNP Wasm builder image =="
docker build -f "$DOCKERFILE_PATH" -t "$IMAGE_NAME" "$ROOT_DIR"

echo "== building snp-verifier-component =="
docker run --rm \
  -v "$ROOT_DIR:/work" \
  -w /work \
  -e SNP_COMPONENT_REL="$SNP_COMPONENT_REL" \
  "$IMAGE_NAME" \
  bash -c '
    if command -v cargo >/dev/null 2>&1; then
      CARGO_BIN=cargo
    elif [ -x /usr/local/cargo/bin/cargo ]; then
      CARGO_BIN=/usr/local/cargo/bin/cargo
    else
      echo "cargo not found in container PATH=$PATH" >&2
      exit 127
    fi

    BUILD_ROOT=/tmp/snp-wasm-min-workspace
    rm -rf "$BUILD_ROOT"
    mkdir -p "$BUILD_ROOT"
    cp -a "/work/$SNP_COMPONENT_REL" "$BUILD_ROOT/snp-verifier-component"

    cat > "$BUILD_ROOT/Cargo.toml" << "EOF"
[workspace]
members = ["snp-verifier-component"]
resolver = "2"

[workspace.dependencies]
anyhow = "1.0"
base64 = "0.22.1"
ciborium = "0.2.2"
hex = "0.4.3"
openssl = "0.10.75"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
strum = { version = "0.27", features = ["derive"] }
tracing = "0.1.43"
EOF

    # Pin this isolated workspace build to Rust 1.90.0 so it matches the
    # toolchain expected by its transient dependency set.
    cd "$BUILD_ROOT"
    export RUSTUP_TOOLCHAIN=1.90.0

    env -u OPENSSL_NO_PKG_CONFIG CFLAGS= CXXFLAGS= \
      RUSTFLAGS="-C target-feature=+simd128" \
      OPENSSL_DIR=/opt/openssl/out/openssl-wasip2-simd \
      OPENSSL_STATIC=1 \
      "$CARGO_BIN" build \
        --manifest-path "$BUILD_ROOT/Cargo.toml" \
        -p snp-verifier-component \
        --release \
        --target wasm32-wasip2

    mkdir -p /work/target/wasm32-wasip2/release
    cp "$BUILD_ROOT/target/wasm32-wasip2/release/snp_verifier_component.wasm" \
      /work/target/wasm32-wasip2/release/snp_verifier_component.wasm
  '

echo "done: $ROOT_DIR/target/wasm32-wasip2/release/snp_verifier_component.wasm"
