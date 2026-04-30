# Bootloader Verifier Component

This component adds the first software layer above TDX hardware verification.

- It **imports** `trustee:verifier/verifier-interface` and calls the imported `evaluate` (TDX layer).
- It **exports** the same `trustee:verifier/verifier-interface` so it can be used directly by `wasm-verifier-lib`.
- It validates RTMR0 and RTMR1 against reference values.

## Evidence format

You can pass bootloader references in the same JSON evidence that TDX verifier already accepts:

```json
{
  "quote": "<base64-tdx-quote>",
  "cc_eventlog": "<optional-base64-ccel>",
  "pccs_url": "https://optional-pccs-url",
  "expected_rtmr0": "<96 hex chars>",
  "expected_rtmr1": "<96 hex chars>"
}
```

`expected_rtmr0` and `expected_rtmr1` are optional.
If not provided, defaults from `tdx-verifier/test_data/tdx_quote.bin` are used.

## Build and compose

From repo root:

```bash
# one-time install
cargo install wac-cli

# build and compose
bash bootloader-verifier/bootloader-verifier-component/scripts/build-bootloader-composed-component.sh
```

Output:

- `target/wasm32-wasip2/release/bootloader_verifier_component.wasm` (has unresolved verifier-interface import)
- `target/wasm32-wasip2/release/bootloader_tdx_verifier_component.wasm` (composed, ready for host use)

## Run test host

```bash
cargo run -p bootloader-verifier-test -- \
  --component target/wasm32-wasip2/release/bootloader_tdx_verifier_component.wasm \
  --evidence-json bootloader-verifier/test_data/bootloader_evidence.json
```
