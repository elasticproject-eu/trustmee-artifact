# TrustMee Artifact

This repository is an artifact for the paper submission "TrustMee: Self-Verifying Remote Attestation Evidence" to ACM CCS 2026.

The code base is based on the Trustee project.

- `platform-agnostic-attestation-verification/paper-evaluation` includes all the evaluations in the paper and can generate the figures under `platform-agnostic-attestation-verification/paper-evaluation/results`. The following scripts run the evaluation using Docker.

## Run the Evaluation

Build the image from the repo root:

```bash
bash platform-agnostic-attestation-verification/paper-evaluation/docker-build.sh
```

Run the full suite:

```bash
bash platform-agnostic-attestation-verification/paper-evaluation/docker-run.sh
```
