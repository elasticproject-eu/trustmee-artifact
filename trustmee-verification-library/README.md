# TrustMee Verification Library

`wasm-verification-component` is the TrustMee verifier host for Wasm verification components. It reads a TrustMee CMW input, extracts the TrustMee-profile EAT evidence, loads a stapled verification component when present, or resolves the matching component from an OCI repository and caches Wasm verification components locally.

Normative format documents:
- `TRUSTMEE_EAT_PROFILE.md`
- `TRUSTMEE_OUTPUT_EAT_PROFILE.md`
- `TRUSTMEE_CMW_COLLECTION_TYPE.md`

## Related projects

- [TrustMee](../platform-agnostic-attestation-verification) is a modified Trustee implementation that integrates TrustMee as a verifier driver and uses this repository as its verification library.
- [wasm-verification-components](../wasm-verification-components) contains the Wasm verification components that this verifier host can execute.

## Input model

The primary input is a CMW Collection that contains:
- exactly one TrustMee-profile EAT Evidence item
- zero or more endorsements
- optionally a stapled Wasm verification component as an endorsement

TrustMee CMW verification returns a JSON output envelope documented in
`TRUSTMEE_OUTPUT_EAT_PROFILE.md`.

The TrustMee EAT payload carries:
- `component_id`
- `evidence`
- `evidence_type`

If the matching Wasm verification component is not stapled into the CMW, the host resolves it from:
- compiled-in placeholder OCI base: `oci://registry.example.com/trustmee/verifier-components`
- optional override: `--component-repository-hint`
- recommended deployment base: `oci://ghcr.io/<github-owner>/trustmee-verifier-components`

## CLI usage

```bash
cargo run -p wasm-verification-component -- \
  --input <path-to-cmw-file> \
  --component-repository-hint <oci-base> \
  --component-trust-store <trust-store.json> \
  --cache-dir <cache-dir> \
  --compact
```

## Runtime cache controls

By default, the library uses a warm in-memory Wasm verifier cache: component
bytes are compiled and pre-instantiated once, then each verification request
gets a fresh Wasm instance.

Set `TRUSTMEE_WASM_INMEM_CACHE_MODE=hot` to cache and reuse the instantiated
Wasm verifier as well. Set `TRUSTMEE_WASM_INMEM_CACHE_MODE=warm` to force the
default warm mode explicitly.

For cold measurements, `TRUSTMEE_WASM_DISABLE_INMEM_CACHE=1` bypasses the
in-memory cache entirely. That legacy disable switch takes precedence over
`TRUSTMEE_WASM_INMEM_CACHE_MODE`.

## Component trust store

When `--component-trust-store` is provided, the library verifies embedded verifier-component signatures with `wasmsign2` before executing the component.

Trust store JSON:

```json
{
  "signers": [
    {
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "fuel": -1,
      "allow_network": true,
      "valid_until": "2026-12-31T23:59:59Z"
    }
  ]
}
```

Notes:

- `public_key` accepts PEM or OpenSSH text. Hex, base64, and base64url encodings of raw `wasmsign2` key bytes are accepted too.
- `fuel = -1` means unlimited Wasmtime fuel. Any other value must be a non-negative integer.
- `valid_until` must be an RFC3339 UTC timestamp for the trust-store signer entry.
- Signed components must also carry embedded TrustMee signature expiry metadata. Use `wasm-verification-components`' `trustmee-component-signer` tool to add `--signature-expires-at` before signing with `wasmsign2`.

Execution policy:

- CMW verification is restrictive by default.
- An unsigned component runs with `1_000_000_000` Wasmtime fuel and no outbound network access.
- A signed component must verify against exactly one trusted, unexpired signer entry, and its embedded signature expiry metadata must be present and unexpired. The signer entry decides the `fuel` limit and whether outbound network access is allowed.
- If a signature is present but invalid, missing expiry metadata, expired, untrusted, or ambiguous, verification fails before the component is instantiated.
- Direct `verify_bytes` and `verify_paths` calls keep legacy behavior unless a trust store is explicitly supplied.
- Result claim `verifier_component_sha256` is computed over the original component bytes after stripping the embedded signature section and TrustMee signature-expiry metadata. When a signature is validated, `verifier_component_signature_public_key` carries the trusted public key used for that validation.
- CMW component cache identity still uses the exact `component_id` digest from the input, including embedded signature and expiry metadata.

## OCI package mapping

The TrustMee wire format stays digest-based. The host maps that digest onto `wasm_pkg_client` package coordinates at fetch time:

- repository base: `oci://<registry>/<prefix...>/<namespace>/<package>`
- Wasm package ref: `<namespace>:<package>`
- OCI namespace prefix: `<prefix...>/` when extra path segments are present before the final two segments
- component version: `component_id = component-<sha256>` maps to package version `0.0.0-component.sha<sha256>`

Examples:

- `oci://ghcr.io/acme/trustmee-verifier-components`
  - package: `acme:trustmee-verifier-components`
  - version for a component digest: `0.0.0-component.sha0123...`
- `oci://ghcr.io/webassembly/acme/trustmee-verifier-components`
  - package: `acme:trustmee-verifier-components`
  - namespace prefix: `webassembly/`
- `file:///tmp/local-registry/acme/trustmee-verifier-components`
  - local backend root: `/tmp/local-registry`
  - package: `acme:trustmee-verifier-components`

## Recommended registry

For public or shared verifier components, use GitHub Container Registry (`ghcr.io`):

- it is a standard OCI registry
- public packages can be pulled anonymously
- `wasm-pkg-tools` already documents GHCR-backed Wasm package layouts
- it fits the package mapping above without introducing TrustMee-specific registry requirements

For private internal deployments, use either private GHCR or a self-hosted OCI registry such as Harbor. The TrustMee client-side mapping stays the same.

## Publishing components to GHCR

1. Choose a base such as `oci://ghcr.io/<github-owner>/trustmee-verifier-components`.
2. Build the Wasm component and compute its TrustMee `component_id`.
3. Convert that digest to the package version `0.0.0-component.sha<sha256>`.
4. Publish the component to package `<github-owner>:trustmee-verifier-components` at that version.

The simplest flow uses `wkg` from `wasm-pkg-tools`.

Example config at `~/.config/wasm-pkg/config.toml`:

```toml
[registry."ghcr.io"]
type = "oci"
[registry."ghcr.io".oci]
auth = { username = "<github-username>", password = "<github-pat-with-write:packages>" }
```

Example publish command:

```bash
wkg publish ./path/to/verifier_component.wasm \
  --package <github-owner>:trustmee-verifier-components@0.0.0-component.sha<sha256> \
  --registry ghcr.io
```

Notes:

- For private GHCR packages, readers need `read:packages`.
- In GitHub Actions, you can usually publish with `GITHUB_TOKEN` when the package is associated with the workflow repository.
- If you publish programmatically, use `wasm_pkg_client::Client::publish_release_data` or `publish_release_file` with the same package/version mapping shown above.

## TrustMee CMW shape

JSON CMW records are encoded as:

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

The inner JSON EAT payload uses:

```json
{
  "eat_profile": "https://trustmee.invalid/eat/component-evidence",
  "component_id": "component-<sha256-of-wasm-bytes>",
  "evidence_type": "application/octet-stream",
  "evidence": "<base64url(raw evidence bytes)>"
}
```

CBOR CMW input is accepted too. The integration tests cover both JSON and CBOR variants.

## Sample artifacts

The `test_data/` directory includes sample verification components and evidence files for local testing:

- `test_data/tdx_verifier_component.wasm`
- `test_data/snp_verifier_component.wasm`
- `test_data/snp_verifier_host_crypto_component.wasm`
- `test_data/tdx_quote.bin`
- `test_data/snp_evidence.json`

Signed sample assets are available under `test_data/signature-demo/`:

- `test_data/signature-demo/snp_verifier_component.private.pem`
- `test_data/signature-demo/snp_verifier_component.public.pem`
- `test_data/signature-demo/snp_verifier_component.trust-store.json`
- `test_data/signature-demo/snp_verifier_component.signed.wasm`

These files are for local testing only.

## Manual SNP Signature Demo

Run the ready-made manual test script:

```bash
./scripts/test_snp_signature_manual.sh
```

The script checks:

- unsigned SNP component without a trust store succeeds
- signed SNP component with the sample trust store succeeds
- signed SNP component with an expired trust store fails
- signed SNP component without a trust store still succeeds in direct mode for compatibility

## Tests

```bash
cargo test -p wasm-verification-component --test sample_library_usage -- --nocapture
cargo test -p wasm-verification-component --test cmw_input -- --nocapture
```
