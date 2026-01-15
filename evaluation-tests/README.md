# Evaluation Tests 

This folder reproduces the performance tests. The scripts target:

- Trustee integration (native AS vs Wasm-based AS)
  - AMD SEV-SNP: end-to-end latency, verifier time, step breakdown, no-cert latency, RSS/CPU usage
  - Intel TDX: end-to-end latency, verifier time, RSS/CPU usage

## Prerequisites

- Rust toolchain (`cargo`, `rustup`)
- `wasm32-wasip2` target installed (`rustup target add wasm32-wasip2`)
- Intel DCAP libs for native TDX verification (e.g., `libsgx-dcap-quote-verify-dev`)
- Network access:
  - AMD KDS for SNP no-cert test
  - Intel PCS/PCCS for TDX collateral
- Wasm OpenSSL for SNP Wasm component (set `OPENSSL_DIR`)

## Quick start (run everything)

From the repo root (WSL):

```bash
bash evaluation-tests/run_all.sh
```

Results are written to `evaluation-tests/results`.

for current version:
```bash
PCCS_URL="https://sgx-dcap-server.cn-beijing.aliyuncs.com/sgx/certification/v4/" OPENSSL_DIR=/path/to/openssl-wasm/ NATIVE_OPENSSL_DIR=/path/to/openssl-native/ bash evaluation-tests/run_all.sh
```

## Build artifacts only

```bash
bash evaluation-tests/bin/build_artifacts.sh
```

## Run tests individually

Start a native AS:

```bash
PORT=18080 AS_VERIFICATION_TIMING_JSON=1 \
  bash evaluation-tests/bin/start_restful_as.sh native
```

Measure SNP end-to-end latency (100 runs):

```bash
python3 evaluation-tests/bin/eval_latency.py \
  --url http://127.0.0.1:18080/attestation \
  --tee snp \
  --runs 100 \
  --output evaluation-tests/results/snp_native_latency.json
```

Parse verifier-only timing from the AS log:

```bash
python3 evaluation-tests/bin/parse_timings.py \
  --log evaluation-tests/tmp/restful-as-native.log \
  --event as_verifier_timing \
  --tee Snp \
  --mode native \
  --output evaluation-tests/results/snp_native_verifier_time.json
```

Stop AS:

```bash
bash evaluation-tests/bin/stop_restful_as.sh native
```

## Wasm-based AS (component registration)

Start Wasm-enabled AS:

```bash
PORT=18080 AS_VERIFICATION_TIMING_JSON=1 \
  bash evaluation-tests/bin/start_restful_as.sh wasm
```

Register a component and run TDX latency:

```bash
COMPONENT_ID="$(python3 evaluation-tests/bin/register_component.py \
  --url http://127.0.0.1:18080/component \
  --component target/wasm32-wasip2/release/tdx_verifier_component.wasm)"

python3 evaluation-tests/bin/eval_latency.py \
  --url http://127.0.0.1:18080/attestation \
  --tee tdx \
  --component-id "$COMPONENT_ID" \
  --runs 100 \
  --output evaluation-tests/results/tdx_wasm_latency.json
```

## Notes

- The verifier timing and SNP step breakdown are emitted as JSON lines to the AS log when `AS_VERIFICATION_TIMING_JSON=1` and `SNP_STEP_TIMING_JSON=1` are set.
- The SNP step breakdown uses `SNP_TIMING_MODE` to tag logs (`native` or `wasm`).
- The SNP no-cert tests can hit AMD KDS rate limits. Use a larger `--interval` and retry settings (as in `evaluation-tests/run_all.sh`) if you see HTTP 429 errors.
- TDX verification may need additional time to fetch collateral; increase `--timeout` or use a local PCCS if you see timeouts.
- Native TDX verification requires a QCNL config. `evaluation-tests/bin/start_restful_as.sh` sets `QCNL_CONF_PATH` (and `SGX_QCNL_CONFIG_FILE`) to `evaluation-tests/tmp/sgx_default_qcnl.conf` by default; override with `QCNL_CONFIG_PATH=/path/to/sgx_default_qcnl.conf` to point to a PCCS.
- **TDX Native Verification in WSL/Non-Standard Environments**: If you encounter `SGX_QL_NO_QUOTE_COLLATERAL_DATA` errors when verifying TDX quotes natively, the QCNL config needs `use_secure_cert: false` to disable SSL certificate verification. This is necessary for environments like WSL where certificate validation may fail. The config file is auto-generated in `evaluation-tests/tmp/sgx_default_qcnl.conf` with this setting.
