# TrustMee E2E Perf Helpers

This helper area turns the manual TrustMee attestation flow into reusable scripts and
adds an end-to-end SNP benchmark runner for the Attestation Service.

Everything here is isolated from product code. Runtime state and generated artifacts are
written under this folder's `results/` tree or under an explicit user-provided output path.
The scripts copy the default policy bundle from
`attestation-service/tests/coco-as/policy` into per-run work directories so repo-tracked
policy files are not mutated during local runs.

## Layout

- `manual/start-restful-as.sh`: build and launch `restful-as` for local TrustMee testing
- `manual/send-trustmee-attestation.sh`: build a TrustMee EAT + CMW request and send it
- `manual/send-native-snp-attestation.sh`: build a native SNP request and send it
- `manual/run-three-cache-requests.sh`: 3-request cache-source experiment (no cache -> disk -> memory)
- `bench/run-snp-e2e-benchmarks.sh`: run the requested SNP end-to-end scenarios
- `lib/common.sh`: shared shell helpers
- `results/`: default output location for manual runs and benchmark runs

## Manual Flow

Start the service:

```bash
./evaluation/trustmee-e2e-perf/manual/start-restful-as.sh --release
```

In another terminal, send the TrustMee request:

```bash
./evaluation/trustmee-e2e-perf/manual/send-trustmee-attestation.sh
```

Or send the same sample evidence through the native SNP verifier path:

```bash
./evaluation/trustmee-e2e-perf/manual/send-native-snp-attestation.sh
```

To omit the stapled Wasm component (requires the component to be resolvable
from cache or OCI by `component_id`):

```bash
./evaluation/trustmee-e2e-perf/manual/send-trustmee-attestation.sh --unstapled
```

To run a 3-request cache-source experiment (prints DISK/MEMORY HIT/MISS trace lines):

```bash
./evaluation/trustmee-e2e-perf/manual/run-three-cache-requests.sh
```

This experiment uses a stapled TrustMee request for the prime request, then unstapled
requests for the fresh-process and warm-process follow-up requests.

The manual request helpers save the generated request artifacts and the returned token
under `evaluation/trustmee-e2e-perf/results/manual/` by default.

## Benchmarks

Run all SNP end-to-end scenarios in release mode:

```bash
./evaluation/trustmee-e2e-perf/bench/run-snp-e2e-benchmarks.sh --release
```

By default the benchmark runner uses:

- `20` measured iterations
- `3` warmup requests
- `test_data/trustmee-lib/snp_evidence.json`
- `test_data/trustmee-lib/snp_verifier_component.wasm`
- `test_data/trustmee-lib/snp_verifier_host_crypto_component.wasm`

Each run creates `results/<timestamp>/` with:

- one `*.summary.txt` per scenario
- one `*.samples.csv` per scenario
- one `restful-as.log` per scenario
- generated config/request artifacts under each scenario directory
- one top-level `comparison.summary.txt`

For the TrustMee Wasm scenarios, the benchmark runner generates two request variants:

- a stapled prime request used to seed the component caches
- an unstapled steady-state request used for warmup and measured iterations

## Notes

- The benchmark script measures the `/attestation` HTTP POST only.
- Fresh-process scenarios exclude service startup and readiness wait time from the recorded
  latency.
- The default SNP sample evidence includes `cert_chain`, so the default runs stay offline.
- The default TrustMee sample assets, including the signed SNP demo assets, are vendored under
  `test_data/trustmee-lib/`, so the helpers keep working even if sibling repos are not present.
