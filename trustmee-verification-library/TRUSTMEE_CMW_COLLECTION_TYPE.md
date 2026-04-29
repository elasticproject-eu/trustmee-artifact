# TrustMee CMW Collection Type

This document defines the TrustMee-specific CMW wrapper contract used by `trustmee-verification-library`.

CMW does not use an EAT-style profile identifier here. Instead, TrustMee defines a collection type identifier and the collection rules associated with that identifier.

## Collection Type Identifier

The TrustMee CMW collection type identifier is:

`https://trustmee.invalid/cmw/verification-input`

A CMW collection for this library MUST carry this exact value in `__cmwc_t`.

## Collection Semantics

A conforming TrustMee CMW collection:
- MUST contain exactly one Evidence entry.
- MAY contain zero or more Endorsement entries.
- MUST use the TrustMee EAT profile as the payload of the Evidence entry.

This collection type currently recognizes only these CMW indicator values:
- Endorsement: `2`
- Evidence: `4`

Any other indicator value is unsupported for this collection type.

## Evidence Entry

The single Evidence entry:
- MUST use indicator `4`
- MUST carry media type `application/eat-ucs+json` or `application/eat-ucs+cbor`
- MUST include the EAT media-type parameter `eat_profile="https://trustmee.invalid/eat/component-evidence"`
- MUST contain an inner TrustMee-profile EAT payload as defined in `TRUSTMEE_EAT_PROFILE.md`

## Endorsement Entries

Each Endorsement entry:
- MUST use indicator `2`
- MAY carry any verifier-specific endorsement payload
- is forwarded to the selected verifier component as:
  - `label`
  - `media_type`
  - `payload`

One standardized endorsement media type is currently defined:
- `application/vnd.trustmee.snp-collateral+cbor`

This is used for stapled SNP collateral.

## Stapled Wasm Component Endorsement

An Endorsement with media type `application/wasm` is treated specially by the host.

Rules:
- The Wasm bytes MUST hash to the `component_id` declared by the enclosed TrustMee EAT.
- The collection MUST NOT contain more than one matching stapled Wasm component.
- A non-matching stapled Wasm component is invalid for this collection type.
- The selected stapled Wasm component is consumed by the host and is not forwarded as an endorsement to the verifier component.

If no matching stapled Wasm component is present, the host resolves the verifier component externally using `component_id`. The CMW collection does not carry a verifier URL or OCI reference.

The repository mapping remains out-of-band:
- the final two configured repository-base path segments select Wasm package `<namespace>:<package>`
- any earlier configured path segments become the OCI namespace prefix
- `component_id = component-<sha256>` maps to package version `0.0.0-component.sha<sha256>`

## JSON Encoding

In JSON form:
- the collection MUST be a JSON object
- `__cmwc_t` MUST be a string
- each entry value MUST be an array of three items:
  1. media type string
  2. base64url payload string
  3. indicator integer

Example:

```json
{
  "__cmwc_t": "https://trustmee.invalid/cmw/verification-input",
  "evidence": [
    "application/eat-ucs+json; eat_profile=\"https://trustmee.invalid/eat/component-evidence\"",
    "<base64url(EAT JSON payload)>",
    4
  ],
  "verifier": [
    "application/wasm",
    "<base64url(wasm bytes)>",
    2
  ],
  "snp-collateral": [
    "application/vnd.trustmee.snp-collateral+cbor",
    "<base64url(CBOR collateral)>",
    2
  ]
}
```

## CBOR Encoding

In CBOR form:
- the collection MUST be a CBOR map
- `__cmwc_t` MUST be a text string
- each entry value MUST be an array of three items:
  1. media type text string
  2. payload byte string
  3. indicator unsigned integer

CBOR entry labels MAY be:
- text strings
- unsigned integers

If a CBOR label is an unsigned integer, the host normalizes it to its base-10 text form before forwarding it to the verifier component as an endorsement label.

## CDDL

The following CDDL describes the TrustMee CMW wrapper shapes used by this library.

Notes:
- The CDDL below models entry structure, not all semantic constraints.
- The descriptive rules below remain authoritative for:
  - exactly one Evidence entry
  - the requirement that the Evidence entry contain a TrustMee-profile EAT
  - stapled Wasm digest matching against `component_id`
- In JSON CMW, payload bytes are base64url strings represented as `tstr`.
- In CBOR CMW, payload bytes are represented as `bstr`.

```cddl
trustmee-cmw-type-id = "https://trustmee.invalid/cmw/verification-input"
trustmee-eat-profile-id = "https://trustmee.invalid/eat/component-evidence"

base64url-bytes = tstr
media-type = tstr
json-label = tstr
cbor-label = tstr / uint

trustmee-eat-json-media-type =
  "application/eat-ucs+json; eat_profile=\"https://trustmee.invalid/eat/component-evidence\""

trustmee-eat-cbor-media-type =
  "application/eat-ucs+cbor; eat_profile=\"https://trustmee.invalid/eat/component-evidence\""

trustmee-eat-media-type = trustmee-eat-json-media-type / trustmee-eat-cbor-media-type

trustmee-json-evidence-entry = [
  trustmee-eat-media-type,
  base64url-bytes,
  4
]

trustmee-json-endorsement-entry = [
  media-type,
  base64url-bytes,
  2
]

trustmee-cbor-evidence-entry = [
  trustmee-eat-media-type,
  bstr,
  4
]

trustmee-cbor-endorsement-entry = [
  media-type,
  bstr,
  2
]

trustmee-cmw-json = {
  "__cmwc_t" => trustmee-cmw-type-id,
  + json-label => trustmee-json-evidence-entry / trustmee-json-endorsement-entry
}

trustmee-cmw-cbor = {
  "__cmwc_t" => trustmee-cmw-type-id,
  + cbor-label => trustmee-cbor-evidence-entry / trustmee-cbor-endorsement-entry
}
```

## Processing Rules

The host processes a TrustMee CMW collection in this order:
1. Parse JSON or CBOR CMW.
2. Validate `__cmwc_t`.
3. Find exactly one Evidence entry.
4. Parse and validate the enclosed TrustMee-profile EAT.
5. Resolve the verifier component from:
   - a matching stapled `application/wasm` endorsement, or
   - external OCI resolution using `component_id`
6. Forward the EAT `evidence` and `evidence_type`, plus all non-Wasm endorsements, to the selected verifier component.
