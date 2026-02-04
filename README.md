# TrustMee Artifact

This repository is an artifact for the paper submission "TrustMee: Self-Verifying Remote Attestation Evidence" to USENIX Security 2026.

The code base is based on the Trustee project.

- `wasm-components` includes the WebAssembly verification components we designed and implemented.
- `evaluation-tests` includes all the evaluations in the paper and can generate all the figures. It can all be run using Docker.

## Run in Docker

Build the image from the repo root:

```bash
docker build -f evaluation-tests/Dockerfile -t trustee-eval .
```

Run the full suite (results are written to the mounted folders):

```bash
docker run --rm \
  -e PCCS_URL="https://api.trustedservices.intel.com/sgx/certification/v4/" \
  -v "$(pwd)/evaluation-tests/results:/work/evaluation-tests/results" \
  -v "$(pwd)/evaluation-tests/attestation-results:/work/evaluation-tests/attestation-results" \
  -v "$(pwd)/evaluation-tests/tmp:/work/evaluation-tests/tmp" \
  trustee-eval
```

Note: the test will perform 100 runs. If it takes too long or hits a rate limit, update `evaluation-tests/run_all.sh` and lower `--samples 100` and `--runs 100`.
