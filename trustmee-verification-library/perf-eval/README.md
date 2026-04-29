# perf-eval

This folder is for evaluation binaries, not for code that is part of the `wasm-verification-component` library API.

Run the two evaluation commands from the `trustmee-verification-library/` directory:

```bash
cargo run --release --bin snp-perf-eval -- --component test_data/snp_verifier_component.wasm --evidence test_data/snp_evidence.json --cache-dir .wasm-verification-component-snp-perf-cache --iterations 20 --warmup 3

cargo run --release --bin snp-perf-eval -- --component test_data/snp_verifier_host_crypto_component.wasm --evidence test_data/snp_evidence.json --cache-dir .wasm-verification-component-snp-host-crypto-perf-cache --iterations 20 --warmup 3

cargo run --release --bin snp-native-perf-eval -- --evidence test_data/snp_evidence.json --cache-dir .native-snp-perf-cache --iterations 20 --warmup 3
```

Files in this folder:

- `snp_perf.rs`: measures the Wasm-based verifier path through `WasmVerificationComponent`.
- `snp_native_perf.rs`: measures a native-only SNP path for comparison.
- `native_snp/`: evaluation-only support code used by `snp_native_perf.rs`.

`native_snp` is not part of the library itself. It exists only to make a like-for-like native benchmark possible. It reuses the SNP verification logic for evaluation, keeps its own vendor cert files, and replaces the Wasm-side environment with small native shims for cache-directory preopens and HTTP VCEK fetching.
