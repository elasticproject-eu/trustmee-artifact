# syntax=docker/dockerfile:1.7
FROM ghcr.io/webassembly/wasi-sdk:wasi-sdk-29 AS wasi-sdk

FROM rust:1.90.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    git \
    gnupg \
    libclang-dev \
    libssl-dev \
    make \
    patch \
    perl \
    pkg-config \
    python3 \
    python3-matplotlib \
    python3-numpy \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install wasmsign2-cli --version 0.2.6

# Intel SGX DCAP dependencies (amd64 only).
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
    curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
      gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" \
      > /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y --no-install-recommends \
      libsgx-dcap-quote-verify \
      libsgx-dcap-quote-verify-dev \
      libsgx-dcap-default-qpl && \
    rm -rf /var/lib/apt/lists/*; \
  fi

COPY --from=wasi-sdk /opt/wasi-sdk /opt/wasi-sdk

ENV WASI_SDK_PATH=/opt/wasi-sdk
ENV WASI_SDK_ROOT=/opt/wasi-sdk

ARG OPENSSL_VERSION=3.5.4
RUN mkdir -p /opt/openssl/src /opt/openssl/native /opt/openssl/wasip2 /opt/openssl/out && \
  curl -fsSL -o /tmp/openssl-${OPENSSL_VERSION}.tar.gz \
    https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
  tar -xzf /tmp/openssl-${OPENSSL_VERSION}.tar.gz -C /opt/openssl/src && \
  cp -a /opt/openssl/src/openssl-${OPENSSL_VERSION} /opt/openssl/native/openssl-${OPENSSL_VERSION} && \
  cp -a /opt/openssl/src/openssl-${OPENSSL_VERSION} /opt/openssl/wasip2/openssl-${OPENSSL_VERSION}

RUN cd /opt/openssl/native/openssl-${OPENSSL_VERSION} && \
  PREFIX_NATIVE=/opt/openssl/out/openssl-native && \
  rm -rf "$PREFIX_NATIVE" && \
  CFLAGS="-O3 -march=native" CXXFLAGS="-O3 -march=native" \
    perl ./Configure linux-x86_64 shared \
      --prefix="$PREFIX_NATIVE" \
      --openssldir="$PREFIX_NATIVE/ssl" && \
  make -j"$(nproc)" && \
  make install_sw

RUN cd /opt/openssl/wasip2/openssl-${OPENSSL_VERSION} && \
  PREFIX_WASI=/opt/openssl/out/openssl-wasip2-simd && \
  rm -rf "$PREFIX_WASI" && \
  CC=/opt/wasi-sdk/bin/wasm32-wasip2-clang \
  AR=/opt/wasi-sdk/bin/llvm-ar \
  RANLIB=/opt/wasi-sdk/bin/llvm-ranlib \
  NM=/opt/wasi-sdk/bin/llvm-nm \
  CFLAGS="-O3 -msimd128" \
  CXXFLAGS="-O3 -msimd128" \
    perl ./Configure gcc \
      --prefix="$PREFIX_WASI" \
      --openssldir="$PREFIX_WASI/ssl" \
      no-shared no-dso no-asm \
      no-apps no-tests \
      no-sock no-dgram \
      no-threads no-async \
      no-engine no-secure-memory \
      no-ui-console no-autoload-config && \
  make -j"$(nproc)" && \
  make install_sw

RUN rustup target add wasm32-wasip2

WORKDIR /work
COPY . /work

RUN chmod +x evaluation-tests/run_all.sh \
  evaluation-tests/bin/*.sh \
  evaluation-tests/docker-entrypoint.sh

ENTRYPOINT ["bash", "evaluation-tests/docker-entrypoint.sh"]
