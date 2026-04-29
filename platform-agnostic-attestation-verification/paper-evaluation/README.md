# Paper Evaluation

Evaluations that compare the native Trustmee attestation-service verifier
against the Wasm-based verifier, plus related cache/crypto breakdowns. Evals
1-6 run by default; eval 7, which measures collateral-fetch network overhead,
is opt-in. Everything is wired together by a single `run_all.sh`; a Dockerfile
packages the toolchain so it can run on any Linux host.

## What is measured

Each eval runs **50 iterations** and writes a JSON summary
(`{runs, mean_ms, std_ms, min_ms, max_ms}`) plus a PDF figure. The shared E2E
driver also writes `logs/*_attestation_result.json` for each latency run; each
file contains the attestation result returned by the first measured request
after any warm-up requests.

| # | Eval                                                   | Key output files                                                                                                     | Figure                                   |
|---|--------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| 1 | E2E latency **without** collateral fetch (cold wasm)   | `eval1_{snp,tdx}_{native,wasm}_latency.json`, `eval1_tdx_native_collateral_time.json`                                | `eval1_e2e_no_collateral.pdf`            |
| 1 | Same, but with the wasm in-mem component cache ON      | `eval1_{snp,tdx}_wasm_latency_hot.json` (native reused from above)                                                   | `eval1_e2e_no_collateral_hot.pdf`        |
| 1 | Hot-cache comparison plus SNP host-crypto and native TDX dcap-qvl bars | eval1 hot inputs plus `eval5_snp_host_crypto_latency.json`, `eval6_tdx_native_verifier_dcap_qvl.json`                 | `eval1_e2e_no_collateral_hot_plus_verifiers.pdf` |
| 2 | Wasm load+instantiate vs verify breakdown (SNP, TDX)   | `eval2_{snp,tdx}_wasm_breakdown.json`                                                                                | `eval2_wasm_load_vs_verify.pdf`          |
| 3 | Cold vs warm vs hot in-memory Wasm verifier cache (E2E) | `eval3_{snp,tdx}_wasm_latency_{cold,warm,hot}.json`                                                                  | `eval3_cold_vs_hot.pdf`                  |
| 3 | Cold vs warm in-memory Wasm verifier cache (E2E)       | `eval3_{snp,tdx}_wasm_latency_{cold,warm}.json`                                                                      | `eval3_cold_vs_hot_4bar.pdf`             |
| 3 | Cold vs warm vs hot — AS-verifier span only            | `eval3_{snp,tdx}_wasm_verifier_{cold,warm,hot}.json`                                                                 | `eval3_cold_vs_hot_verifier.pdf`         |
| 3 | Eval3 merged with eval2 cold-start breakdowns          | eval2 breakdowns plus eval3 E2E warm/hot inputs                                                                      | `eval3_cold_vs_hot_merged.pdf`, `eval3_cold_vs_hot_4bar_merged.pdf` |
| 4 | SNP step breakdown (cert, signature, other)            | `eval4_snp_{native,wasm}_step_breakdown.json` (`cert_chain_ms`, `signature_ms`, `others_ms` from the same evaluate run) | `eval4_snp_step_breakdown.pdf`, `eval4_snp_step_breakdown_pie.pdf` |
| 5 | SNP host-crypto vs wasm-crypto (in-mem cache on)       | `eval5_snp_{wasm,host}_crypto_latency.json`                                                                          | `eval5_snp_host_vs_wasm_crypto.pdf`      |
| 6 | TDX native-dcap-qvl vs wasm parity (verifier time)     | `eval6_tdx_{native,wasm}_verifier_dcap_qvl.json`                                                                     | `eval6_tdx_dcap_qvl_parity.pdf`          |
| 7 | E2E **with** collateral fetch (no caches)              | `eval7_{snp,tdx}_{native,wasm}_latency.json`                                                                         | `eval7_e2e_with_collateral.pdf`          |
| — | Attestation REST body sizes (one-off, not 50×)         | `request_sizes.json`, `request_size_requests/` — native / wasm-stapled / wasm-component-id body sizes, with exact no-collateral baseline/component-id request bodies | n/a |
| — | wasmtime compile times (one-off)                       | `compile_times.json` — per-component `Component::from_binary` time without and with the on-disk compilation cache (5 runs per regime, mean/std/min/max) | n/a |

## Quick start (dockerized)

From the parent directory:

```bash
bash platform-agnostic-attestation-verification/paper-evaluation/docker-build.sh
bash platform-agnostic-attestation-verification/paper-evaluation/docker-run.sh

# Run only eval 7, the network-overhead measurement.
bash platform-agnostic-attestation-verification/paper-evaluation/docker-run.sh --network-overhead

# Also generate secondary/detail figures.
bash platform-agnostic-attestation-verification/paper-evaluation/docker-run.sh --more-detail
```

Results land in
`platform-agnostic-attestation-verification/paper-evaluation/results/<timestamp>/`,
including `system_info.txt`.

By default, figure generation omits the detail-only PDFs
`eval1_e2e_no_collateral_hot_plus_verifiers.pdf`,
`eval3_cold_vs_hot_merged.pdf`, and `eval4_snp_step_breakdown_pie.pdf`.
Pass `--more-detail` or set `MORE_DETAIL=1` to include them.

Wasm request bodies use CBOR CMW/EAT by default to avoid nested base64 inside
the TrustMee wrapper. Set `TRUSTMEE_CMW_FORMAT=json` to reproduce the legacy
JSON CMW/EAT request format.

## Run natively (no docker)

Requires: Rust 1.90, `rustup target add wasm32-wasip2`, `libsgx-dcap-quote-verify-dev`
(for native TDX), matplotlib + numpy + `cbor2` for Python.

```bash
# Native OpenSSL (shared) + WASI-p2 OpenSSL (static) must be built / installed.
export NATIVE_OPENSSL_DIR=/path/to/openssl-native
export OPENSSL_DIR=/path/to/openssl-wasip2
bash platform-agnostic-attestation-verification/paper-evaluation/run_all.sh

# Run only eval 7, the network-overhead measurement.
NETWORK_OVERHEAD=1 bash platform-agnostic-attestation-verification/paper-evaluation/run_all.sh

# Also generate secondary/detail figures.
bash platform-agnostic-attestation-verification/paper-evaluation/run_all.sh --more-detail
```

## Code modifications (minimal, env-gated)

All additions outside `paper-evaluation/` default to no-ops unless an env var
is set. They are:

* `platform-agnostic-attestation-verification/Cargo.toml` — `[patch]` entry
  redirecting the `wasm-verification-component` git dep to the local
  `../trustmee-verification-library/` path.
* `attestation-service/src/paper_eval_timing.rs` + one call site in
  `lib.rs`: emits an `as_verifier_timing` JSON line when
  `AS_VERIFICATION_TIMING_JSON=1`.
* `deps/verifier/src/snp/mod.rs`:
  - `SNP_VCEK_DISABLE_CACHE=1` bypasses the Moka HTTP cache in
    `build_vcek_client`.
  - `SNP_STEP_TIMING_JSON=1` emits an `snp_step_timing` event.
* `deps/verifier/src/intel_dcap/mod.rs`:
  - Wraps `tee_qv_get_collateral` with a timer; emits
    `as_tdx_collateral_timing` when `AS_VERIFICATION_TIMING_JSON=1`.
* `deps/verifier/src/intel_dcap_qvl/mod.rs` (new, feature-gated):
  - Native TDX verification via the pure-Rust `dcap-qvl` crate (the same
    library the wasm TDX verifier uses).
  - Activated by `TDX_NATIVE_USE_DCAP_QVL=1` when the
    `tdx-verifier-dcap-qvl` Cargo feature is built in.
* `trustmee-verification-library/src/lib.rs`:
  - `TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1` bypasses the in-memory
    loaded/pre-instantiated component cache (wasmtime's disk cache still
    applies).
  - `TRUSTMEE_WASM_INMEM_CACHE_MODE=warm|hot` selects the warm
    loaded/pre-instantiated verifier cache (default) or the hot
    instantiated-verifier cache. The disable switch above still wins.
  - `TRUSTMEE_WASM_DISABLE_WASMTIME_CACHE=1` bypasses Wasmtime's on-disk
    compiled-component cache.
  - `WASM_TIMING_JSON=1` emits `wvc_{load,instantiate,verify,total}_timing`.
  - Re-emits legacy component timing claims as log events, then strips them
    before returning verifier claims.
* `wasm-verification-components/tdx-verifier/...`:
  - Accepts a CMW endorsement with media type
    `application/vnd.trustmee.tdx-collateral+cbor` whose payload is
    `dcap_qvl::QuoteCollateralV3` as CBOR. Skips PCS fetch when present.
  - With `WVC_EMIT_TIMING=1`, emits collateral timing as a JSON log event;
    timing fields are not returned as claims.
* `wasm-verification-components/tdx-verifier/dcap-qvl-wasi/`:
  - New `reqwest-http` cargo feature that plugs in a `reqwest::blocking`
    backend for native builds.
* `wasm-verification-components/snp-verifier/.../snp.rs` (and host-crypto
  variant):
  - With `WVC_EMIT_TIMING=1`, emits SNP step timing as JSON log events;
    timing fields are not returned as claims.
* `trustmee-verification-library/src/trustmee_input.rs`:
  - Adds the `TDX_COLLATERAL_MEDIA_TYPE` constant.
  - `TRUSTMEE_WASM_DISABLE_COMPONENT_FILE_CACHE=1` bypasses the component-byte
    file cache used for component-id-only CMWs.

## Helper binary

`paper-evaluation/tools/fetch-tdx-collateral/` — a standalone crate that runs
`dcap-qvl-wasi`'s collateral fetcher once and writes the CBOR payload that the
eval scripts embed in the CMW.

## Layout

```
paper-evaluation/
├── README.md
├── Dockerfile
├── docker-entrypoint.sh
├── docker-build.sh
├── docker-run.sh
├── run_all.sh                 # single-entry orchestrator
├── bin/                       # python helpers + bash lifecycle scripts
│   ├── build_artifacts.sh
│   ├── start_restful_as.sh
│   ├── stop_restful_as.sh
│   ├── eval_env.sh            # sourced by each eval_scripts/*.sh
│   ├── eval_common.py
│   ├── eval_latency.py
│   ├── parse_timings.py
│   ├── build_cmw.py
│   ├── build_snp_native_body.py
│   ├── build_tdx_native_body.py
│   ├── extract_snp_cert_chain_cbor.py
│   ├── write_system_info.sh
│   └── plot_figures.py
├── eval_scripts/              # one script per evaluation
│   ├── eval1_no_collateral_latency.sh
│   ├── eval2_wasm_load_vs_verify.sh
│   ├── eval3_cold_vs_hot_wasm_cache.sh
│   ├── eval4_snp_step_breakdown.sh
│   ├── eval5_snp_host_vs_wasm_crypto.sh
│   ├── eval6_tdx_dcap_qvl_parity.sh
│   └── eval7_with_collateral_latency.sh
├── tools/
│   └── fetch-tdx-collateral/  # rust helper to fetch TDX collateral -> CBOR
└── results/                   # populated at runtime, one dir per run
```
