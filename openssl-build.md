# OpenSSL 3.5.4 build guide for Trustee (native + wasm32-wasip2)

This repository uses OpenSSL in two places:
- Native builds (restful AS, KBS, verifier tooling).
- Wasm SNP verifier component (wasm32-wasip2, static libs).

This guide builds OpenSSL 3.5.4 twice, in separate folders:
- Native shared build: `libssl.so` / `libcrypto.so`
- WASI Preview 2 build: static `libssl.a` / `libcrypto.a` with SIMD128

References:
- https://github.com/openssl/openssl/releases
- https://github.com/WebAssembly/wasi-sdk

## 0) Workspace layout

```bash
export WORK="$HOME/work/openssl-3.5.4-build"
mkdir -p "$WORK"/{src,native,wasip2,out}
cd "$WORK"
```

## 1) Download OpenSSL 3.5.4 (GitHub tarball)

```bash
cd "$WORK/src"

curl -L -o openssl-3.5.4.tar.gz \
  https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz

tar xf openssl-3.5.4.tar.gz

# Duplicate the tree so native/wasm builds do not step on each other
cp -a openssl-3.5.4 "$WORK/native/openssl-3.5.4"
cp -a openssl-3.5.4 "$WORK/wasip2/openssl-3.5.4"
```

## 2) Native build (shared)

### 2.1 Install dependencies (Ubuntu/WSL)

```bash
sudo apt-get update
sudo apt-get install -y build-essential perl make curl ca-certificates
```

### 2.2 Configure + build + install

```bash
cd "$WORK/native/openssl-3.5.4"

export PREFIX_NATIVE="$WORK/out/openssl-native"
rm -rf "$PREFIX_NATIVE"

# Optimization (native SIMD via -march=native)
export CFLAGS="-O3 -march=native"
export CXXFLAGS="-O3 -march=native"

# Shared build
perl ./Configure linux-x86_64 shared \
  --prefix="$PREFIX_NATIVE" \
  --openssldir="$PREFIX_NATIVE/ssl"

make -j"$(nproc)"
make test
make install_sw
```

### 2.3 Quick sanity check

```bash
"$PREFIX_NATIVE/bin/openssl" version -a
ldd "$PREFIX_NATIVE/bin/openssl" | grep -E 'libssl|libcrypto' || true
```

Notes:
- The evaluation scripts default to `OPENSSL_STATIC=1`. If you want to use this
  shared build, set `OPENSSL_STATIC=0` (or unset it) when building native binaries.
- If you prefer a fully static native build, configure without `shared` and add
  `no-shared` instead.

## 3) WASI Preview 2 build (wasm32-wasip2, SIMD128, static libs)

WASI currently has no dynamic libraries and no networking. The WASI build must
use `no-shared` and disable socket BIOs (`no-sock`, `no-dgram`).

### 3.1 Build inside the wasi-sdk Docker image

```bash
export PREFIX_WASI="$WORK/out/openssl-wasip2-simd"
rm -rf "$PREFIX_WASI"

docker run --rm -it \
  -v "$WORK:/work" \
  -w /work/wasip2/openssl-3.5.4 \
  ghcr.io/webassembly/wasi-sdk:wasi-sdk-29 \
  bash
```

### 3.2 Inside the container: configure + build + install

```bash
set -euxo pipefail

# Toolchain
export CC=/opt/wasi-sdk/bin/wasm32-wasip2-clang
export AR=/opt/wasi-sdk/bin/llvm-ar
export RANLIB=/opt/wasi-sdk/bin/llvm-ranlib
export NM=/opt/wasi-sdk/bin/llvm-nm

# O3 + wasm SIMD128
export CFLAGS="-O3 -msimd128"
export CXXFLAGS="-O3 -msimd128"

export PREFIX=/work/out/openssl-wasip2-simd
rm -rf "$PREFIX"

perl ./Configure gcc \
  --prefix="$PREFIX" \
  --openssldir="$PREFIX/ssl" \
  no-shared no-dso no-asm \
  no-apps no-tests \
  no-sock no-dgram \
  no-threads no-async \
  no-engine no-secure-memory \
  no-ui-console no-autoload-config

make -j"$(nproc)"
make install_sw
```

Exit the container (`exit`).

### 3.3 Check outputs on the host

```bash
ls "$PREFIX_WASI"/include/openssl | head
ls "$PREFIX_WASI"/lib | grep -E 'lib(ssl|crypto)\.(a|so)' || true
```

You should see `libcrypto.a` and usually `libssl.a` under `"$PREFIX_WASI/lib"`.

## 4) Use the builds in this repo

### 4.1 Wasm SNP verifier component (required for wasm32-wasip2)

```bash
export OPENSSL_DIR="$WORK/out/openssl-wasip2-simd"
RUSTFLAGS='-C target-feature=+simd128' \
  OPENSSL_DIR="$OPENSSL_DIR" \
  cargo build -p snp-verifier-component --release --target wasm32-wasip2
```

### 4.2 Evaluation tests (native + wasm)

```bash
export OPENSSL_DIR="$WORK/out/openssl-wasip2-simd"
export NATIVE_OPENSSL_DIR="$WORK/out/openssl-native"

# If you followed the shared build, unset OPENSSL_STATIC or set it to 0.
export OPENSSL_STATIC=0

bash evaluation-tests/run_all.sh
```

### 4.3 Native builds only

```bash
export OPENSSL_DIR="$WORK/out/openssl-native"
export PATH="$OPENSSL_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$OPENSSL_DIR/lib:$LD_LIBRARY_PATH"

# Example: build the RESTful AS binary against this OpenSSL
OPENSSL_NO_PKG_CONFIG=1 OPENSSL_DIR="$OPENSSL_DIR" \
  cargo build -p attestation-service \
  --no-default-features \
  --features "restful-bin,snp-verifier,tdx-verifier" \
  --bin restful-as \
  --release
```
