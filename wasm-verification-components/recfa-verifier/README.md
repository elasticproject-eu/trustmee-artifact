# ReCFA verification component

A TrustMee Wasm verification component wrapping the verifier from
**ReCFA: Resilient Control-Flow Attestation** (ACSAC'21) —
[paper](https://arxiv.org/abs/2110.11603),
[code](https://github.com/suncongxd/ReCFA).

ReCFA is a *control-flow* attestation scheme: the attester runs a statically
instrumented binary that records every function call, indirect jump and return,
condenses that stream, and ships it as the attestation report. The verifier
replays the stream against a CFI policy using a shadow stack, and reports the
exact control-flow edge that violated the policy.

## What is ported, and how

The verification logic is upstream's `src/verifier/check.cpp`, vendored under
`recfa-verifier-component/vendor/` and compiled to `wasm32-wasip2` with wasi-sdk.
It is **not** a rewrite: `readAsmFile`, `readDyninst`, `readTypeAmror`,
`readForToNext`, `FtoN`, `verifi` and `verifiSecond` are byte-identical to
upstream, including the regexes. The Rust crate is only WIT glue.

`vendor/check.cpp` is generated, not hand-edited. Regenerate and inspect the diff
with:

```bash
cd recfa-verifier-component/vendor
python3 patch-upstream.py /path/to/ReCFA/src/verifier/check.cpp
```

The script applies a fixed list of exact-match edits, each with an asserted
occurrence count, so it either reproduces the vendored file or fails loudly.
Every deviation is tagged `/* RECFA-PORT */` in the output. The edits, and why
each is necessary:

| Category | Change | Why |
|---|---|---|
| portability | `+#include <map>`, `+<stack>`, `+<cstdint>` | libc++ does not pull these in transitively; g++ does |
| portability | `-#include <thread>` | unused, and drags in a threading impl the sandbox lacks |
| portability | 5 × `fstream f(path)` → `RecfaIn f(path)`, 1 × `fopen` → `recfa_fopen` | inputs arrive as memory buffers, so the component needs **no filesystem at all** |
| no-trap | 4 × `exit(-1)` → set a fatal code, return | a Wasm trap is a host error, not a verdict; the guest must always return JSON |
| verdict | assignments at the 4 verdict sites | so the shell reads a status code instead of scraping stdout |

## Interface

**Evidence** — the folded control-flow event stream from the attester
(`*_instru-re_folded`); media type `application/octet-stream`. A sequence of
little-endian `u32` events, consumed as (source, target) pairs:

| value | meaning |
|---|---|
| plain address | one element of a (source, target) pair |
| high bit set (`v & 0x80000000`) | `v - 0x80000000` is a *direct call site*; the verifier re-injects its statically known target, so the pair costs one event instead of two |
| `0xffffeeee` | start of another execution of `main` (multi-run traces) |
| `0x7fffeeee` | end-of-program marker |

Note the verifier consumes the **`_folded`** file, not the `_gr` / `.zst` files
produced later by `compress.sh`.

**Endorsements** (reference values — none of this is hardcoded):

| label | media type | content |
|---|---|---|
| `recfa-disassembly` | `text/plain` | `objdump -d` of the attested binary. **Must come from binutils ≤ 2.34** (see below) |
| `recfa-cfg` | `text/vnd.graphviz` | `bin/preCFG` output (Dyninst ParseAPI `.dot`) |
| `recfa-policy-f` | `text/plain` | patched-typearmor `binfo.*`: legal indirect-call targets |
| `recfa-policy-m` | `text/plain` | csfilter `*.filtered.map`: skipped direct call sites. Optional; empty means no call-site filtering |
| `recfa-config` | `application/json` | `{"compiler_type":"gcc"\|"llvm","num_executions":N}` |

`compiler_type` is **not** cosmetic: it selects which register the indirect-jump
regex matches (`gcc` → `jmpq *%rax`, `llvm` → `jmpq *%rcx`). The wrong value
silently drops every indirect jump from the policy, so the component rejects
anything other than those two strings.

**`expected-report-data`** — ReCFA evidence has no report-data field, so when the
host supplies one it is bound to the trace: the first 32 bytes must equal
`sha256(evidence)` and the rest must be zero. That lets a caller, or an enclosing
TEE quote, commit to exactly this event stream.

**`expected-init-data-hash`** — ReCFA has no init-data measurement. If one is
supplied the component **fails closed** rather than ignoring it; compose under a
TEE verifier if you need that binding.

**Claims** on success:

```json
{
  "attester_type": "recfa",
  "hardware_rooted": false,
  "evidence_sha256": "c2f2…",
  "report_data_bound": false,
  "recfa": {
    "verdict": "secure",
    "events_attested": 9,
    "events_reconstructed": 0,
    "events_unprocessed": 0,
    "policy_f_call_sites": 3,
    "policy_m_entries": 0,
    "compiler_type": "gcc",
    "num_executions": 1,
    "main_addr": "0x401000",
    "main_ret_addr": "0x401050",
    "evidence_bytes": 40,
    "evidence_events": 10
  },
  "reference_values": {
    "disassembly_sha256": "cf03…",
    "cfg_sha256": "1fbd…",
    "policy_f_sha256": "f2cb…",
    "policy_m_sha256": "e3b0…"
  }
}
```

The four `reference_values` digests let a Trustee policy pin the exact CFG and
policy files the verdict was computed against — otherwise "secure" only means
"secure with respect to whatever policy was supplied".

On any CFI violation the component fails closed with a top-level `error`, keeping
the diagnostics alongside it:

```json
{
  "status": "failed",
  "error": "indirect-call-violation at 0x401020: target 0x401100 is not permitted",
  "recfa": { "verdict": "indirect-call-violation", "events_attested": 2, … }
}
```

Verdicts: `secure`, `shadow-stack-violation`, `indirect-call-violation`,
`indirect-jump-violation`, `cfg-policy-m-inconsistent`, `policy-f-inconsistent`.

## `hardware_rooted: false` — read this before trusting a verdict

ReCFA is **not** a TEE scheme, and its evidence is unauthenticated. From §2.2 of
the paper:

> "we assume the kernel combined with the hardware-assisted protection keys
> (MPK) [22] as the trust anchor of the prover, which is reasonable against
> user-level attackers and for commodity hardware."

> "ensuring the freshness and authenticity of our attestation report between the
> prover and verifier can rely on the state-of-the-art attestation protocol and a
> trust anchor."

So the trust anchor is *kernel + Intel MPK*, and freshness/authenticity is
delegated to some other protocol. Neither is implemented in the released
artifact: the instrumentation simply `fopen()`s a file and appends events — there
is no signature, MAC, or nonce anywhere in `src/mutator/`.

Consequences for deployment:

* A verdict of `secure` says only "this byte stream is a control-flow-integral
  execution of the binary described by these reference values". It does **not**
  say the stream came from the machine you think, at the time you think, or that
  it was not replayed or fabricated.
* Bind it to something. Either use `expected-report-data` (above), or compose
  this component under a TEE verifier so a hardware quote covers the trace
  digest. `wit/verifier.wit` keeps the layered world in a comment for exactly
  this; switching to it requires no change to the vendored C++:

```bash
wac plug target/wasm32-wasip2/release/recfa_verifier_component.wasm \
  --plug target/wasm32-wasip2/release/tdx_verifier_component.wasm \
  -o target/wasm32-wasip2/release/recfa_tdx_verifier_component.wasm
```

ReCFA additionally assumes DEP is enabled on the prover, and excludes physical
attacks, data-only attacks, self-modifying code, JIT, and unanticipated dynamic
loading.

## Build

```bash
rustup target add wasm32-wasip2
export WASI_SDK_PATH=$HOME/wasi-sdk        # wasi-sdk >= 24
cargo build -p recfa-verifier-component --release --target wasm32-wasip2
```

Or use the script, which also validates the component and runs the tests:

```bash
recfa-verifier-component/scripts/build-recfa-wasm-component.sh --test
RECFA_UPSTREAM=/path/to/ReCFA \
  recfa-verifier-component/scripts/build-recfa-wasm-component.sh --parity
```

Two build-flag notes:

* `-fno-exceptions`. clang's `-fwasm-exceptions` currently emits *legacy* EH
  opcodes, which the wasmtime version this repo pins rejects. The vendored
  verifier never throws, so this costs nothing. Because libc++ then aborts
  instead of throwing, `src/lib.rs` bounds every input (size, NUL bytes, maximum
  line length) in safe Rust before the C++ sees it.
* `_WASI_EMULATED_PROCESS_CLOCKS`. Upstream calls `clock()` only to report its
  own runtime; WASI has no process clock, so the emulation is linked in.

## Test

The fixture in `test_data/` is a small hand-built program with a known-correct
CFG, generated by `test_data/gen_fixture.py`. It covers a direct call, the
compressed direct-call encoding, an indirect call, an indirect jump, policy-M
call-site reconstruction, and one case for each violation class:

```bash
cargo build -p recfa-verifier-test
../../target/debug/recfa-verifier-test \
  --component ../../target/wasm32-wasip2/release/recfa_verifier_component.wasm \
  --disassembly test_data/prog.asm --cfg test_data/prog.dot \
  --policy-f test_data/binfo.prog --batch test_data --compiler gcc
```

```
CASE               VERDICT                    EVENTS   RESULT
fail_icall         indirect-call-violation    2        OK
fail_ijmp          indirect-jump-violation    2        OK
fail_shadow        shadow-stack-violation     3        OK
pass_compressed    secure                     5        OK
pass_icall         secure                     9        OK
pass_ijmp          secure                     3        OK
pass_policy_m      secure                     11       OK
pass_simple        secure                     5        OK

PASS: all 8 cases behaved as expected
```

### End to end on a custom binary

`test_data/` is a synthetic fixture: hand-built disassembly, CFG and policies with
hand-encoded event streams. For the real chain — a program compiled here,
statically instrumented with Dyninst, **executed**, and verified from the events
that run recorded, with policy F produced by the patched typearmor pass instead of
written by hand — see [custom-e2e/](custom-e2e/):

```bash
bash custom-e2e/build.sh --test
```

It builds both attester toolchains as containers (Dyninst 10.1 for ReCFA, Dyninst
9.3.1 for typearmor, so no VM is needed), regenerates every artifact, and runs two
end-to-end tests against the Wasm component: the untampered run verifies, and the
`tools/make-tamper.py` hijack is rejected with the offending edge named.

### Parity with unmodified upstream

The real correctness argument for the port is that it agrees with the original
binary. `tools/parity-check.py` runs unmodified upstream `check` and the vendored
verifier over identical inputs and compares verdict, `|M|`, `|F|`, attested event
count, and queue depth on failure:

```
CASE               VERDICT                    EVENTS   |M|/|F|  PARITY
fail_icall         indirect-call-violation    2        0/3      OK
fail_ijmp          indirect-jump-violation    2        0/3      OK
fail_shadow        shadow-stack-violation     3        0/3      OK
pass_compressed    secure                     5        0/3      OK
pass_icall         secure                     9        0/3      OK
pass_ijmp          secure                     3        0/3      OK
pass_policy_m      secure                     11       1/3      OK
pass_simple        secure                     5        0/3      OK

PASS: vendored verifier matches upstream on all 8 cases
```

Note this compares the *vendored C++* against upstream. The Wasm component
produces the same event counts on the same fixture (table above), so the chain
upstream → vendored → Wasm is covered end to end.

### Real SPEC CPU2006 evidence

Validated against genuine attester output for `bzip2_base.gcc_O0`: a 10.8 MB
folded trace (2,708,524 events) with the CFG generated by Dyninst 10.1 `preCFG`
and the disassembly by binutils 2.30. Reference data in `test_data/spec/`
(`ATTESTER_SETUP.md` explains how to reproduce it).

All three implementations agree, on clean and tampered evidence alike:

| case | upstream `check` | vendored C++ | Wasm component |
|---|---|---|---|
| unmodified trace | `secure`, 3615494 events | `secure`, 3615494 | `secure`, 3615494 |
| indirect call retargeted | `Indirect Call` | `indirect-call-violation`, 34 | `indirect-call-violation`, 34 |
| return target corrupted | `fail,1808279 unprocessed`, 1807217 events | `shadow-stack-violation`, 1807217 / 1808279 | `shadow-stack-violation`, 1807217 / 1808279 |

`|M|` = 134, `|F|` = 460 and `events_reconstructed` = 3282 in every run. Note the
attested count (3,615,494) exceeds the trace length (2,708,524): the difference is
policy-M call-site reconstruction re-inserting the filtered-out direct calls.

The tampered traces are derived by `tools/make-tamper.py`, which retargets a real
indirect call to a function policy F does not permit *at that site* — a realistic
hijack rather than random corruption. The component pinpoints it:

```
"error": "indirect-call-violation at 0x4067e6: target 0x4009d0 is not permitted"
```

To reproduce:

```bash
python3 tools/make-tamper.py \
  test_data/spec/bzip2_base.gcc_O0_instru-re_folded \
  test_data/spec/binfo.bzip2_base.gcc_O0

../../target/debug/recfa-verifier-test \
  --component ../../target/wasm32-wasip2/release/recfa_verifier_component.wasm \
  --disassembly test_data/spec/bzip2_base.gcc_O0.asm \
  --cfg         test_data/spec/bzip2_base.gcc_O0.dot \
  --policy-f    test_data/spec/binfo.bzip2_base.gcc_O0 \
  --policy-m    test_data/spec/bzip2_base.gcc_O0.filtered.map \
  --trace       test_data/spec/bzip2_base.gcc_O0_instru-re_folded \
  --compiler gcc --num-executions 2 --expect secure
```

Performance: ~1.1 s native versus ~21 s through wasmtime for the 2.7 M-event
trace, the latter including component instantiation, JIT compilation and copying
10.8 MB of evidence across the component boundary. The 10.8 MB trace and 1.2 MB
disassembly sit comfortably inside a 32-bit linear memory.

Getting there needs Dyninst 10.1 for the `.dot` and the authors' Google Drive
traces; the repo ships the binaries, policy `F` and policy `M` but neither of
those. One trap worth repeating: `check.cpp` matches `callq`, `jmpq   *%rax` and `retq`.
binutils ≥ 2.35 prints `call`, `jmp` and `ret` without the `q`, so a modern
`objdump` silently yields a disassembly in which **no call site is found at all**
(`|F|` = 0 and every trace "passes"). Generate `.asm` with binutils ≤ 2.34.

## Caveats

* Upstream writes progress to stdout (`|M|= …`, `Nevents sucess`, …). Those
  writes are preserved to keep the diff minimal, so the component is chatty on
  stdout; the verdict is carried entirely in the returned JSON.
* The chunked streaming path in upstream (`sto.size() > 10000000`) is preserved,
  but the whole event stream is resident in linear memory, so a 32-bit Wasm
  guest caps the practical trace size. The component enforces a 512 MiB evidence
  limit and 256 MiB per text endorsement.
* `num_executions` must match how many runs of `main` the trace contains,
  exactly as with upstream's `verify.sh`.
