# TrustMee Artifact

This repository contains the artifact for the paper submission "TrustMee: Self-Verifying Remote Attestation Evidence."

The code base is based on the Trustee project.

- `platform-agnostic-attestation-verification/paper-evaluation` includes all the evaluations in the paper and can generate the figures under `platform-agnostic-attestation-verification/paper-evaluation/results`. Only Docker is required on the host to run the evaluation.

## Run the Evaluation

Build the image from the repo root:

```console
docker build --platform=linux/amd64 -f platform-agnostic-attestation-verification/paper-evaluation/Dockerfile -t trustmee-paper-eval .
```

Run the full suite:

```console
docker run --rm --platform=linux/amd64 -e RUNS=50 -e NETWORK_OVERHEAD=0 -e MORE_DETAIL=0 -v "$PWD/platform-agnostic-attestation-verification/paper-evaluation/results:/work/platform-agnostic-attestation-verification/paper-evaluation/results" trustmee-paper-eval
```
