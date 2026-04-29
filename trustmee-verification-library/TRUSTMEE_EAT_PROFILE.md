# TrustMee EAT Profile

This document defines the EAT profile used by `trustmee-verification-library` for encapsulated attestation Evidence that carries a component identifier.

## Profile Identifier

The TrustMee EAT profile identifier is:

`https://trustmee.invalid/eat/component-evidence`

An EAT that claims conformance to this profile:
- MUST carry this exact identifier in the inner `eat_profile` claim.
- MUST also carry this exact identifier in the outer EAT media-type parameter `eat_profile` when the EAT is wrapped in CMW.

## Supported EAT Media Types

This profile is carried only in:
- `application/eat-ucs+json`
- `application/eat-ucs+cbor`

When this profile is used, the outer media type MUST include:

`eat_profile="https://trustmee.invalid/eat/component-evidence"`

Example:

```text
application/eat-ucs+json; eat_profile="https://trustmee.invalid/eat/component-evidence"
```

## UJCS/UCCS Secure-Channel Requirement

`application/eat-ucs+json` and `application/eat-ucs+cbor` are the EAT media types for
unprotected claims sets:
- `application/eat-ucs+json` carries EAT as UJCS
- `application/eat-ucs+cbor` carries EAT as UCCS

These formats do not provide COSE- or JOSE-level protection by themselves.
Accordingly, this TrustMee profile MUST only be used when the surrounding
conveyance or execution environment provides equivalent protection.

At minimum, the surrounding mechanism MUST provide:
- sender authentication
- integrity protection

If the EAT contents are confidentiality sensitive, the surrounding mechanism
MUST also provide:
- receiver authentication
- confidentiality protection

Replay protection MUST be provided by the surrounding protocol, channel, or
freshness mechanism. In TrustMee deployments, this is typically handled by the
attestation protocol that conveys the CMW-wrapped EAT.

This requirement follows the security guidance for UCCS/UJCS in RFC 9781 and
the media-type registrations in RFC 9782.

## Required Claims

This profile defines the following required claim names and value formats.

### `eat_profile`

- Type: text string
- Required: yes
- Value: exactly `https://trustmee.invalid/eat/component-evidence`

### `component_id`

- Type: text string
- Required: yes
- Value format: `component-<64 lowercase hex characters>`
- Meaning: SHA-256 digest of the selected verifier Wasm component bytes, prefixed with `component-`

Example:

```text
component-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### `evidence_type`

- Type: text string
- Required: yes
- Meaning: media type of the raw attestation evidence carried in `evidence`

Examples:
- `application/octet-stream`

The host treats this as opaque metadata and passes it to the selected verifier component.

### `evidence`

- Type in the abstract profile: byte string
- Required: yes
- Meaning: raw attestation evidence bytes for the selected verifier component

Encoding rules:
- In `application/eat-ucs+json`, `evidence` MUST be a base64url-encoded string representation of the bytes.
- In `application/eat-ucs+cbor`, `evidence` MUST be encoded as a CBOR byte string.

Producers SHOULD emit unpadded base64url in JSON. Receivers SHOULD accept both padded and unpadded base64url.

## JSON Form

The JSON EAT payload uses these exact key names:

```json
{
  "eat_profile": "https://trustmee.invalid/eat/component-evidence",
  "component_id": "component-<sha256-of-verifier-wasm-bytes>",
  "evidence_type": "application/octet-stream",
  "evidence": "<base64url(raw-evidence-bytes)>"
}
```

## CBOR Form

The CBOR EAT payload MAY use either:
- the exact text keys below, or
- the integer keys defined below

Text key names:
- `eat_profile`
- `component_id`
- `evidence_type`
- `evidence`

Integer keys:
- `265`: `eat_profile` (the standard EAT CBOR label)
- `65537`: `component_id`
- `65538`: `evidence_type`
- `65539`: `evidence`

CBOR value types:
- `eat_profile`: text string
- `component_id`: text string
- `evidence_type`: text string
- `evidence`: byte string

Example CBOR logical map using integer keys:

```text
{
  265: "https://trustmee.invalid/eat/component-evidence",
  65537: "component-<sha256-of-verifier-wasm-bytes>",
  65538: "application/octet-stream",
  65539: h'<raw-evidence-bytes>'
}
```

## CDDL

The following CDDL describes the TrustMee EAT profile payload shapes.

Notes:
- The CDDL below models structure, not every semantic rule.
- This CDDL does not check that component_id has the required digest format.
- `base64url-bytes` is represented as `tstr`.
- The preferred CBOR encoding for `evidence` is `bstr`.
- The implementation also accepts a CBOR byte-array compatibility form for `evidence`.

```cddl
trustmee-eat-profile-id = "https://trustmee.invalid/eat/component-evidence"

component-id = tstr
media-type = tstr
base64url-bytes = tstr

trustmee-eat-json = {
  "eat_profile" => trustmee-eat-profile-id,
  "component_id" => component-id,
  "evidence_type" => media-type,
  "evidence" => base64url-bytes,
  * tstr => any
}

trustmee-eat-cbor = trustmee-eat-cbor-text / trustmee-eat-cbor-int

trustmee-eat-cbor-text = {
  "eat_profile" => trustmee-eat-profile-id,
  "component_id" => component-id,
  "evidence_type" => media-type,
  "evidence" => trustmee-evidence-bytes,
  * (tstr / int) => any
}

trustmee-eat-cbor-int = {
  265 => trustmee-eat-profile-id,   ; eat_profile
  65537 => component-id,            ; component_id
  65538 => media-type,              ; evidence_type
  65539 => trustmee-evidence-bytes, ; evidence
  * (tstr / int) => any
}

trustmee-evidence-bytes = bstr / [* uint]
```

## Processing Rules

A TrustMee-profile EAT is valid for this library only if all of the following hold:
- The outer EAT media type is `application/eat-ucs+json` or `application/eat-ucs+cbor`.
- The outer media-type parameter `eat_profile` is present and exactly matches the TrustMee profile identifier.
- The inner `eat_profile` claim is present and exactly matches the TrustMee profile identifier.
- `component_id` is present and matches the required digest syntax.
- `evidence_type` is present.
- `evidence` is present.

Additional claims MAY be present, but `trustmee-verification-library` currently defines and depends on the required claims listed above.

## Explicit Non-Goals

This profile does not carry a verifier download URL.

Verifier component location is resolved outside the EAT:
- first from a stapled `application/wasm` endorsement in the enclosing CMW collection
- otherwise from an out-of-band OCI repository base combined with `component_id`

When the host uses `wasm_pkg_client` for OCI resolution, the out-of-band repository base is mapped as follows:
- the final two base-path segments select Wasm package `<namespace>:<package>`
- any earlier path segments become the OCI namespace prefix
- `component_id = component-<sha256>` maps to package version `0.0.0-component.sha<sha256>`
