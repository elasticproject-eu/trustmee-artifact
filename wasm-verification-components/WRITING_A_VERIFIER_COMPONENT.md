# Writing a new verification component

A verification component is a `wasm32-wasip2` Wasm component that **exports
`trustee:verifier/verifier-interface`** and returns its claims as a JSON string.
The TrustMee host
([`trustmee-lib`](https://github.com/elasticproject-eu/trustmee-lib))
instantiates it in a sandbox, calls `evaluate` exactly once, and feeds the
returned JSON into the Trustee's policy checker engine.

## 1. Crate layout

```
my-verifier/
  my-verifier-component/
    Cargo.toml
    wit/verifier.wit
    src/lib.rs
```

Add the crate to `members` in the root `Cargo.toml`:

```toml
members = [
    "my-verifier/my-verifier-component",
    # …
]
```

`my-verifier/my-verifier-component/Cargo.toml`:

```toml
[package]
name = "my-verifier-component"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]     # required: this is what makes it a component
test = false
doctest = false

[package.metadata.component]
package = "trustee:verifier"

[dependencies]
serde_json.workspace = true
wit-bindgen = "0.46.0"
```

Keep verification logic in a separate plain-Rust crate (like
`kata-policy-verifier/kata-policy-core`) so you can unit-test it natively with
`cargo test`; the component crate is only WIT glue.

## 2. The WIT — copy it, do not redesign it

```bash
mkdir -p my-verifier/my-verifier-component/wit
cp tdx-verifier/tdx-verifier-component/wit/verifier.wit \
   my-verifier/my-verifier-component/wit/verifier.wit
```

The `interface verifier-interface` block must stay **identical** to the host's
copy in `trustmee-lib/wit/verifier.wit` (that is what the host
binds against). Only the `world` at the bottom is yours:

```wit
// leaf verifier (verifies evidence itself)
world verifier {
  export verifier-interface;
}
```

```wit
// layered verifier (calls another verifier underneath)
world my-verifier {
  import verifier-interface;
  export verifier-interface;
}
```

The world name must match `world:` in `wit_bindgen::generate!`.

## 3. What `evaluate` must do

```wit
evaluate: func(
  input: verifier-input,              // evidence + media type + endorsements
  expected-report-data: report-data,  // optional-data
  expected-init-data-hash: init-data-hash,
) -> string                           // JSON
```

Inputs:

| field | contents |
|---|---|
| `input.evidence` | raw evidence bytes, from the TrustMee EAT `evidence` claim |
| `input.evidence-media-type` | the EAT `evidence_type` (e.g. `application/octet-stream`, `application/json`) |
| `input.endorsements` | all non-`application/wasm` CMW endorsements: `label`, `media-type`, `payload` |
| `expected-report-data` | `value(bytes)` → you **must** check the evidence binds it; `not-provided` → skip |
| `expected-init-data-hash` | same, for MRCONFIGID (TDX) / HOSTDATA (SNP) |

Output — exactly one JSON string:

* **success**: a JSON **object** of claims. Emit *facts*, not just booleans, so
  Trustee policy can appraise them. The host adds `verifier_component_sha256`
  (and the signer key when signed) to that object.
* **failure**: `{"status":"failed","error":"…"}` — the host treats **any
  top-level `error` key** as verification failure and rejects the attestation.

Rules:

* **Fail closed.** Every malformed/attacker-controlled input path returns the
  error JSON. Never `unwrap()`/panic — a Wasm trap is a host-level error, not a
  verdict.
* **Always terminate.** An unsigned component runs with `1_000_000_000` Wasmtime
  fuel; a signed one gets whatever `fuel` its trust-store entry says. No
  unbounded loops or blocking waits.
* **Be deterministic**: same evidence + endorsements → same claims.

Minimal leaf skeleton (`src/lib.rs`), same shape as
`kata-policy-verifier/stub-hardware-verifier-component/src/lib.rs`:

```rust
use serde_json::{json, Value};

wit_bindgen::generate!({
    path: "wit",
    world: "verifier",
});

use exports::trustee::verifier::verifier_interface as iface;

fn evaluate_impl(input: &iface::VerifierInput) -> Result<String, String> {
    // 1. parse input.evidence (respect input.evidence_media_type)
    // 2. verify it cryptographically / structurally
    // 3. check expected_report_data / expected_init_data_hash if provided
    // 4. return claims as a JSON object
    let claims = json!({ "tee_type": "my-tee", "my_claim": "…" });
    serde_json::to_string(&claims).map_err(|e| e.to_string())
}

struct Component;
impl iface::Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;
impl iface::GuestVerifier for Verifier {
    fn new() -> Self { Self }

    fn evaluate(
        &self,
        input: iface::VerifierInput,
        _expected_report_data: iface::OptionalData,
        _expected_init_data_hash: iface::OptionalData,
    ) -> String {
        match evaluate_impl(&input) {
            Ok(claims) => claims,
            Err(e) => json!({ "status": "failed", "error": e }).to_string(),
        }
    }
}

export!(Component);
```

## 4. If you already have a native verifier

You do not rewrite it — the component is only a shell around it.

**It is in Rust.** Move the verifier into a plain crate (no WIT) and depend on it
from the component crate; `evaluate_impl` becomes parse-input → call your
library → serialise claims. Then make it build for `wasm32-wasip2`:

* Build for the target first and let the errors drive the port:
  `cargo build -p my-verifier-component --target wasm32-wasip2`. Practically all
  failures come from a dependency that links C code, calls a syscall the target
  does not have, or is `cfg`-gated to native platforms.
* For each such dependency, in order of preference: (1) turn off default features
  and select a pure-Rust backend if the crate offers one (crypto crates usually
  do); (2) replace it with a pure-Rust equivalent; (3) keep it and cross-compile
  its C library for `wasm32-wasip2` yourself, e.g. with `wasi-sdk` inside a
  container so the build is reproducible.
* Drop what the sandbox does not have: threads, sockets, native TLS, subprocesses,
  filesystem paths other than `cache/`, and I/O runtimes such as
  `tokio`/`reqwest`. For HTTP use a WASI HTTP client, behind a cargo feature so
  the crate still builds natively for tests. Wall-clock time and randomness do
  work, so certificate-expiry style checks port unchanged.

All three routes exist in this repo if you want a worked example: the TDX
verifier started from Intel's DCAP QVL, which is C/C++ — it was first swapped for
the pure-Rust `dcap-qvl` crate, i.e. route (2), and then route (1) on top of that
(`default-features = false, features = ["std", "rustcrypto"]`, so no `ring`/C
backend is pulled in). The SNP verifier takes route (3)
(`snp-verifier/snp-verifier-component/scripts/build-snp-wasm-component.sh` builds
OpenSSL for `wasm32-wasip2` in a container), and `tdx-verifier/dcap-qvl-wasi`
shows the feature-gated WASI HTTP client.

**It is not in Rust.** Two options, cheapest first:

* Compile the native library to `wasm32-wasip2` (`wasi-sdk` clang for C/C++) as
  a static lib and keep the Rust component shell, calling it through
  `extern "C"` FFI from `build.rs`/`cc`. All WIT glue stays Rust.
* Write the guest in that language directly: generate bindings for the *same*
  `wit/verifier.wit` with the language's generator (`wit-bindgen c ./wit`,
  `wit-bindgen-go` + TinyGo, `componentize-py`, `jco componentize`). If the
  toolchain emits a core module instead of a component, wrap it:
  `wasm-tools component new module.wasm --adapt wasi_snapshot_preview1.reactor.wasm -o my_verifier_component.wasm`.

## 5. Endorsements

Reference values (approved hashes, expected measurements, certificates,
collateral) arrive as labelled endorsements — do not hardcode them. Look them up
by label and fail on missing *or duplicate* labels
(`kata-policy-verifier-component/src/lib.rs` has the canonical helper):

```rust
fn find_endorsement<'a>(input: &'a iface::VerifierInput, label: &str) -> Result<&'a [u8], String> {
    let mut m = input.endorsements.iter().filter(|e| e.label == label).map(|e| e.payload.as_slice());
    let first = m.next().ok_or_else(|| format!("missing required endorsement `{label}`"))?;
    if m.next().is_some() {
        return Err(format!("duplicate endorsement `{label}`"));
    }
    Ok(first)
}
```

Document your labels in the component's README, e.g.

| label | content |
|---|---|
| `init-data` | full plaintext init-data TOML |
| `approved-templates` | JSON array of sha256 hex digests |

## 6. Composing with another verifier (e.g. call the TDX verifier)

Use the layered world: you `import` the same interface you `export`. Forward the
hardware evidence down, then add your own checks on top. The imported and
exported types are distinct Rust types, so convert field by field:

```rust
wit_bindgen::generate!({ path: "wit", world: "my-verifier" });

use exports::trustee::verifier::verifier_interface as export_iface;
use trustee::verifier::verifier_interface as import_iface;

let hardware = import_iface::Verifier::new();
let hw_out = hardware.evaluate(
    &forward_input(input),                        // clone fields into import_iface::VerifierInput
    &forward_optional(expected_report_data),      // map Value/NotProvided
    &forward_optional(expected_init_data_hash),
);

let hw_claims: Value = serde_json::from_str(&hw_out)
    .map_err(|e| format!("hardware verifier returned non-JSON claims: {e}"))?;
if let Some(err) = hw_claims.get("error") {
    return Err(format!("hardware evidence verification failed: {err}"));   // its failure is your failure
}

// your own checks, e.g. bind to the hardware-measured init-data:
let measured = hw_claims.get("init_data").and_then(Value::as_str).ok_or("no init_data claim")?;

serde_json::to_string(&json!({ "my_layer": my_claims, "hardware": hw_claims }))
```

Both TDX and SNP verifiers in this repo expose the measured init-data register
(MRCONFIGID / HOSTDATA) as a top-level hex `init_data` claim, and their quote
claims under `quote/body/…` (see `bootloader-verifier` reading `rtmr_0`/`rtmr_1`).

Then link the two components with `wac` (the composed component exports **only**
your interface, so it is a drop-in verifier):

```bash
cargo install wac-cli    # once

cargo build -p tdx-verifier-component --release --target wasm32-wasip2
cargo build -p my-verifier-component  --release --target wasm32-wasip2

wac plug target/wasm32-wasip2/release/my_verifier_component.wasm \
  --plug target/wasm32-wasip2/release/tdx_verifier_component.wasm \
  -o target/wasm32-wasip2/release/my_tdx_verifier_component.wasm
```

Copy `kata-policy-verifier/kata-policy-verifier-component/scripts/build-kata-policy-composed-component.sh`
as your build script — it already switches the lower layer with
`LOWER=stub|tdx|snp`. Use a stub lower layer (see
`stub-hardware-verifier-component`) to test without a live TEE. Layers stack:
your composed component can itself be plugged under a higher-level verifier.

## 7. Host sandbox: internet is optional

Inside the host sandbox your component gets:

* **Filesystem**: one preopened directory, `cache/` (for collateral caching).
  Nothing else.
* **Internet**: outbound `wasi:http` exists, but is **denied by default**. An
  unsigned component runs with no network at all; a signed component gets
  network only if its trust-store signer entry has `"allow_network": true`.

So treat network access as an optional accelerator, not a requirement: verify
offline from `input.evidence` + endorsements (stapled collateral, certificates)
whenever possible, and fetch over HTTP only as a fallback — that is what the SNP
verifier does for VCEK (AMD KDS) and the TDX verifier for PCS collateral. When a
request is denied, surface it as a normal `{"status":"failed","error":"…"}` with
a clear message.

## 8. Build

```bash
rustup target add wasm32-wasip2      # once
cargo build --manifest-path Cargo.toml -p my-verifier-component --release --target wasm32-wasip2
```

Output: `target/wasm32-wasip2/release/my_verifier_component.wasm` (crate name,
hyphens → underscores). No `cargo component` needed.

## 9. Sign it and emit a trust store

```bash
cargo run -p trustmee-component-signer -- sign \
  --component target/wasm32-wasip2/release/my_verifier_component.wasm \
  --signed-component target/wasm32-wasip2/release/my_verifier_component.signed.wasm \
  --signature-expires-at 2035-01-01T00:00:00Z \
  --generate-key \
  --private-key-out component.private.pem \
  --public-key-out component.public.pem \
  --trust-store-out component.trust-store.json \
  --valid-until 2035-01-01T00:00:00Z
```

Add `--allow-network=false` if your component must never reach the network, and
`--fuel <n>` to cap its execution. Sign the **composed** `.wasm` when you use
composition — that is the artifact the host runs.

## 10. Run it

Local harness: copy `bootloader-verifier/bootloader-verifier-test` (smallest
example, ~200 lines) — it does `wasmtime::component::bindgen!` against your
`wit/` dir, preopens a fresh `cache/` dir and calls `evaluate`:

```bash
cargo run -p my-verifier-test -- \
  --component target/wasm32-wasip2/release/my_tdx_verifier_component.wasm \
  --evidence-json my-verifier/test_data/evidence.json
```

Through the real host (CMW input, signature + trust store enforced), from
[`trustmee-lib`](https://github.com/elasticproject-eu/trustmee-lib):

```bash
cargo run -p wasm-verification-component -- \
  --input <cmw.json> \
  --component-trust-store component.trust-store.json \
  --cache-dir <cache-dir>
```

## Checklist

- [ ] `wit/verifier.wit` copied verbatim; only the `world` changed
- [ ] crate added to root `Cargo.toml` members; `crate-type = ["cdylib"]`
- [ ] every error path returns `{"status":"failed","error":"…"}`; no panics, no unbounded loops
- [ ] `expected-report-data` / `expected-init-data-hash` honoured when provided
- [ ] reference values taken from endorsements (documented labels), not hardcoded
- [ ] works with no network; HTTP only as fallback
- [ ] claims are facts a Trustee policy can appraise
- [ ] built for `wasm32-wasip2`, composed with `wac plug` if layered, then signed
