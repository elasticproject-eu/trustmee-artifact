This directory contains standalone WebAssembly components used by this project.

- `tdx-verifier-component`: a Wasm *component* implementing the WIT interface (`world verifier`) for Intel TDX quote verification.
- `tdx-verifier-test`: a native host CLI that loads the component with Wasmtime and calls `evaluate` using a local TDX quote (and optional CCEL).
- `snp-verifier-component`: a Wasm *component* implementing the WIT interface (`world verifier`) for AMD SEV-SNP evidence verification.
- `snp-verifier-test`: a native host CLI that loads the component with Wasmtime and calls `evaluate` using a local SNP report (and optional VCEK/VLEK).

## Build the component

From the repo root:

`cargo component build -p tdx-verifier-component --release --target wasm32-wasip1`

The resulting component is created at `target/wasm32-wasip1/release/tdx_verifier_component.wasm`.

For AMD SEV-SNP, the verifier depends on OpenSSL. Build OpenSSL for `wasm32-wasip1` and point `OPENSSL_DIR` to it, and enable SIMD128:

`RUSTFLAGS='-C target-feature=+simd128' OPENSSL_DIR=/path/to/wasm-openssl cargo component build -p snp-verifier-component --release --target wasm32-wasip1`

The resulting component is created at `target/wasm32-wasip1/release/snp_verifier_component.wasm`.

## Run the verifier (host-side)

`cargo run -p tdx-verifier-test -- --component target/wasm32-wasip1/release/tdx_verifier_component.wasm --quote /path/to/tdx-quote.bin`

Optional inputs:

- `--ccel /path/to/ccel.bin`
- `--pccs-url https://api.trustedservices.intel.com` (defaults to Intel PCS)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`
- `--cache-dir <host-dir>` (collateral cache; pre-opened to the component as `cache/`)

On verification failure, the component returns JSON like `{"status":"failed","error":"..."}` and the host exits non-zero.

For AMD SEV-SNP:

`env -u OPENSSL_NO_PKG_CONFIG CFLAGS= CXXFLAGS= cargo run -p snp-verifier-test -- --component target/wasm32-wasip1/release/snp_verifier_component.wasm --report snp_report.bin --vcek sev_snp_quote_and_certs/vcek.der`

Optional inputs:

- `--vlek /path/to/vlek.der` (use VLEK instead of VCEK)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`

If no VCEK/VLEK is provided, the component will fetch VCEK from AMD KDS using WASI-HTTP.

## Smoke test Trustee integration (RESTful-AS)

`bash wasm-components/scripts/smoke-restful-as-wasm-tdx.sh`
