# Manual Test Example (REST + TrustMee CMW)

This guide runs the current attestation-service Wasm flow:

1. Start `restful-as` with the `wasm-verification-component-driver`
2. Prepare a TrustMee CMW file
3. Send one attestation request with `tee = "sample"`

The Wasm backend no longer supports `/component` registration or the older wrapped JSON payload with `component_id`.

## Prerequisites

- Run from repo root.
- Tools: `cargo`, `jq`, `curl`, `base64`.
- A TrustMee CMW file generated according to:
  - `trustmee-verification-library/TRUSTMEE_EAT_PROFILE.md`
  - `trustmee-verification-library/TRUSTMEE_CMW_COLLECTION_TYPE.md`

The CMW may be JSON or CBOR. In both cases, the attestation request carries the raw CMW bytes as base64(URL_SAFE_NO_PAD).

## 1) Start attestation-service (REST)

Create a local config so AS writes only under `/tmp`:

```bash
cat > /tmp/as-trustmee-manual-config.json <<'JSON'
{
  "work_dir": "/tmp/as-trustmee-manual",
  "rvps_config": {
    "type": "BuiltIn",
    "storage": {
      "type": "LocalFs",
      "file_path": "/tmp/as-trustmee-manual/reference_values"
    }
  },
  "attestation_token_broker": {
    "policy_dir": "/tmp/as-trustmee-manual/policies"
  },
  "wasm_component_registry": {
    "component_cache_base_dir": "/tmp/as-trustmee-manual/component-cache"
  }
}
JSON
```

Start RESTful AS:

```bash
RUST_LOG=info,restful_as=debug,attestation_service=info \
cargo run -p attestation-service \
  --no-default-features \
  --features "restful-bin,wasm-verification-component-driver" \
  --bin restful-as -- \
  --config-file /tmp/as-trustmee-manual-config.json \
  --socket 127.0.0.1:8080
```

## 2) Helper for URL-safe base64 without padding

```bash
b64url_file() {
  base64 -w0 "$1" | tr '+/' '-_' | tr -d '='
}
```

## 3) Send a TrustMee attestation request

Assume your TrustMee CMW is available at `/tmp/input.cmw`.

```bash
jq -n \
  --arg evidence "$(b64url_file /tmp/input.cmw)" \
  '{
     verification_requests: [{
       tee: "sample",
       evidence: $evidence
     }],
     policy_ids: ["default"]
   }' > /tmp/attest-trustmee.json

curl -sS -X POST http://127.0.0.1:8080/attestation \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/attest-trustmee.json | tee /tmp/attest-trustmee-token.txt
```

## Notes

- `evidence` is the raw TrustMee CMW payload, not JSON.
- The CMW must contain exactly one TrustMee-profile EAT Evidence item.
- The CMW may staple the Wasm verifier component and endorsements. If it does not, the service falls back to the TrustMee library's OCI resolution behavior.
- `tee` must stay equal to the real target TEE claimed by the wrapped evidence, such as `snp` or `tdx`.
