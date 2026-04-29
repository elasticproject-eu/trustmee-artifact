# WebAssembly Verification Components

This project contains standalone WebAssembly verification components used by TrustMee project.

- `bootloader-verifier/`: bootloader layer component (`bootloader-verifier-component`) that imports TDX verifier interface and verifies RTMR0/RTMR1 policy
- `tdx-verifier/`: TDX-related items (`dcap-qvl-wasi`, `tdx-verifier-component`, `tdx-verifier-test`)
- `snp-verifier/`: SNP-related items (`snp-verifier-component`, `snp-verifier-test`)

## Build the component

From the repo root (no `cargo component` required; uses the native `wasm32-wasip2` target):

`cargo build --manifest-path Cargo.toml -p tdx-verifier-component --release --target wasm32-wasip2`

The resulting component is created at `target/wasm32-wasip2/release/tdx_verifier_component.wasm`.

For AMD SEV-SNP, use the builder script (it builds a containerized toolchain and OpenSSL for `wasm32-wasip2`):

`bash snp-verifier/snp-verifier-component/scripts/build-snp-wasm-component.sh`

The resulting component is created at `target/wasm32-wasip2/release/snp_verifier_component.wasm`.

For the layered bootloader verifier component (imports TDX verifier interface and exports the same interface):

`cargo build --manifest-path Cargo.toml -p bootloader-verifier-component --release --target wasm32-wasip2`

Then compose bootloader + tdx so only bootloader exports are exposed:

`bash bootloader-verifier/bootloader-verifier-component/scripts/build-bootloader-composed-component.sh`

This script uses `wac`.
Install once if needed:
`cargo install wac-cli`

The composed component is written to:
`target/wasm32-wasip2/release/bootloader_tdx_verifier_component.wasm`.


## Run the verifier (host-side)

For Bootloader + TDX:

Run bootloader verifier test host:

`cargo run -p bootloader-verifier-test -- --component target/wasm32-wasip2/release/bootloader_tdx_verifier_component.wasm --evidence-json bootloader-verifier/test_data/bootloader_evidence.json`

For Intel TDX:

`cargo run -p tdx-verifier-test -- --component target/wasm32-wasip2/release/tdx_verifier_component.wasm --quote tdx-verifier/test_data/tdx_quote.bin`

Optional inputs:

- `--ccel /path/to/ccel.bin`
- `--pccs-url https://api.trustedservices.intel.com` (defaults to Intel PCS)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`
- `--cache-dir <host-dir>` (collateral cache base; a fresh subdirectory is pre-opened to the component as `cache/`)

On verification failure, the component returns JSON like `{"status":"failed","error":"..."}` and the host exits non-zero.

For AMD SEV-SNP:

`cargo run -p snp-verifier-test -- --component target/wasm32-wasip2/release/snp_verifier_component.wasm --evidence-json snp-verifier/test_data/snp_evidence.json`

Optional inputs:

- `--vlek /path/to/vlek.der` (use VLEK instead of VCEK)
- `--expected-report-data-hex <hex>`
- `--expected-init-data-hash-hex <hex>`
- `--cache-dir <host-dir>` (VCEK cache base; a fresh subdirectory is pre-opened to the component as `cache/`)

If no VCEK/VLEK is provided, the component will fetch VCEK from AMD KDS using WASI-HTTP.
If the host pre-opens a `cache/` directory for the component, fetched VCEKs are cached there.
Set `SNP_VCEK_DISABLE_CACHE=1` to disable VCEK caching.
