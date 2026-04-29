# Manual Test Example (Docker + gRPC + TrustMee CMW)

This guide runs the current gRPC Wasm flow:

1. Start `grpc-as` from the existing compose stack
2. Prepare a TrustMee CMW file
3. Send one `AttestationEvaluate` request with `tee = "sample"`

The Wasm backend no longer supports `RegisterComponent` or the older wrapped JSON payload with `component_id`.

## Prerequisites

- Run from repo root.
- Tools on host: `docker`, `docker compose`, `jq`, `base64`.
- `sudo` may be required for Docker commands, depending on your setup.
- A TrustMee CMW file generated according to:
  - `trustmee-verification-library/TRUSTMEE_EAT_PROFILE.md`
  - `trustmee-verification-library/TRUSTMEE_CMW_COLLECTION_TYPE.md`

## 1) Start AS using existing compose files

Rebuild `as` with the Wasm verification component driver enabled:

```bash
docker compose down as rvps
docker compose up -d setup
docker compose build --no-cache --build-arg VERIFIER='wasm-verification-component-driver' as
docker compose up -d rvps as
docker compose logs --tail=120 as
```

Confirm the service is up on `50004`:

```bash
docker compose ps
docker compose port as 50004
```

## 2) Helpers

```bash
b64url_file() {
  base64 -w0 "$1" | tr '+/' '-_' | tr -d '=\n'
}

grpcurl_docker() {
  docker run --rm -i --network host \
    -v "$PWD:/work" \
    fullstorydev/grpcurl:latest \
    -plaintext \
    -import-path /work/protos \
    -proto /work/protos/attestation.proto \
    -d @ 127.0.0.1:50004 "$1"
}
```

## 3) Send a TrustMee attestation request

Assume your TrustMee CMW is available at `/tmp/input.cmw`.

```bash
jq -n \
  --arg evidence "$(b64url_file /tmp/input.cmw)" \
  '{
     verificationRequests: [{
       tee: "sample",
       evidence: $evidence
     }],
     policyIds: ["default"]
   }' > /tmp/attest-trustmee-grpc.json

grpcurl_docker attestation.AttestationService/AttestationEvaluate \
  < /tmp/attest-trustmee-grpc.json | tee /tmp/attest-trustmee-grpc-resp.json

jq -r '.attestationToken // .attestation_token' \
  /tmp/attest-trustmee-grpc-resp.json > /tmp/attest-trustmee-token.txt
```

## Troubleshooting

- `connection refused` to `127.0.0.1:50004`:
  - `as` is not up or crashed. Run `docker compose ps` and `docker compose logs --tail=200 as`.
- `method not found` for `RegisterComponent`:
  - This is expected. The gRPC registration API has been removed.
- `feature wasm-verification-component-driver is not enabled`:
  - Rebuild with `--build-arg VERIFIER='wasm-verification-component-driver'`.
- `tee_type` mismatch or a rejected Wasm request:
  - Keep the verifier-produced `tee_type` aligned with the real target TEE carried by the wrapped evidence, for example `snp` or `tdx`.
