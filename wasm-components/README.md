This directory contains standalone WebAssembly components used by this project.

- `tdx-verifier-component`: a Wasm *component* implementing the thesis WIT interface (`world verifier`) for Intel TDX quote verification.
- `tdx-verifier-test`: a native host CLI that loads the component with Wasmtime and calls `evaluate` using a local TDX quote (and optional CCEL).

## Build the component

From the repo root:

`cargo component build -p tdx-verifier-component --release --target wasm32-wasip2`

The resulting component is created at `target/wasm32-wasip1/release/tdx_verifier_component.wasm`.

## Run the verifier (host-side)

`cargo run -p tdx-verifier-test -- --component target/wasm32-wasip1/release/tdx_verifier_component.wasm --quote /path/to/tdx-quote.bin`

Optional inputs:

- `--ccel /path/to/ccel.bin`
- `--pccs-url https://api.trustedservices.intel.com` (defaults to Intel PCS)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`
- `--cache-dir <host-dir>` (collateral cache; pre-opened to the component as `cache/`)

On verification failure, the component returns JSON like `{"status":"failed","error":"..."}` and the host exits non-zero.
