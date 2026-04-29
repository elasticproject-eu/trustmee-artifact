# TrustMee Output EAT Profile

This document defines the minimal JSON result envelope returned by
`trustmee-verification-library` when verifying TrustMee CMW input through
`verify_cmw_bytes` or `verify_cmw_path`.

## Profile Identifier

The TrustMee output profile identifier is:

`https://trustmee.invalid/eat/verification-result`

A TrustMee verification result that claims conformance to this profile:
- MUST carry this exact identifier in the top-level `eat_profile` claim.

## Supported Encoding

This profile is currently defined only for JSON results returned by the
library API.

No media-type parameter, CMW wrapper, or CBOR encoding is currently defined
for this output profile.

## Required Claims

### `eat_profile`

- Type: text string
- Required: yes
- Value: exactly `https://trustmee.invalid/eat/verification-result`

### `tee_type`

- Type: text string
- Required: yes
- Meaning: the verified TEE type reported by the selected verifier component

Examples:
- `snp`
- `tdx`

### `claims`

- Type: JSON object
- Required: yes
- Meaning: verifier-produced claims map for the real TEE evidence

### `verifier_component_sha256`

- Type: text string
- Required: yes
- Value format: 64 lowercase hex characters
- Meaning: SHA-256 digest of the verifier Wasm component bytes that produced the result

## Optional Claims

### `init_data`

- Type: text string
- Required: no
- Meaning: validated init data digest or value promoted to the top-level envelope

### `report_data`

- Type: text string
- Required: no
- Meaning: validated report data digest or value promoted to the top-level envelope

## JSON Form

```json
{
  "eat_profile": "https://trustmee.invalid/eat/verification-result",
  "tee_type": "snp",
  "claims": {
    "measurement": "<verifier-specific value>",
    "reported_tcb_snp": 23
  },
  "verifier_component_sha256": "<64 lowercase hex characters>",
  "init_data": "<optional>",
  "report_data": "<optional>"
}
```

## Processing Rules

A TrustMee output-profile result is valid for this library contract only if all
of the following hold:
- `eat_profile` is present and exactly matches the TrustMee output profile identifier.
- `tee_type` is present and is a string.
- `claims` is present and is a JSON object.
- `verifier_component_sha256` is present and is a lowercase hex SHA-256 digest string.

Additional claims MAY be present, but `trustmee-verification-library` currently
defines only the claims listed above for this output envelope.
