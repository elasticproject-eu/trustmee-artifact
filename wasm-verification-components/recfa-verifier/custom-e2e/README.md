# ReCFA end to end on a custom binary

A complete ReCFA attestation of a program written for this repo: `prog.c` is
compiled, statically instrumented with Dyninst, **run**, and the control-flow
event stream of that run is verified by the TrustMee Wasm component.

No evidence and no policy here is hand-authored. Every input comes from the tool
that produces it upstream:

| input | tool | where it runs |
|---|---|---|
| the binary (`prog`) | `gcc -O0 -no-pie -g` | `recfa-dyninst` |
| disassembly (`prog.asm`) | `objdump -d`, binutils 2.30 | `recfa-dyninst` |
| CFG (`prog.dot`) | `bin/preCFG`, Dyninst 10.1 ParseAPI | `recfa-dyninst` |
| **policy F** (`binfo.prog`) | **patched TypeArmor static pass**, Dyninst 9.3.1 | `recfa-typearmor` |
| policy M (`prog.filtered.map`) | `bin/csfilter.jar` | host (a JRE) |
| instrumented binary (`prog_instru`) | `bin/mutator`, Dyninst 10.1 | `recfa-dyninst` |
| raw events (`prog_instru-re`) | running `prog_instru` | `recfa-dyninst` |
| **evidence** (`prog_instru-re_folded`) | `bin/folding` | `recfa-dyninst` |
| tampered evidence | `../tools/make-tamper.py` | host |

The two Dockerfiles in `attester/` exist because ReCFA needs Dyninst 10.1 while
TypeArmor needs 9.3.1 — upstream tells you to put the second one in a separate
VirtualBox VM; here it is just another container.

## Build it

```bash
bash build.sh          # regenerate every artifact in artifacts/
bash build.sh --test   # ... and run the two end-to-end tests
bash build.sh --test-only   # only the tests, against the committed artifacts
```

The first run builds both images from source (Dyninst twice — tens of minutes and
a few GB) and clones upstream ReCFA (~185 MB) into `.upstream/`. Set
`RECFA_UPSTREAM` to an existing checkout to skip the clone, and `RECFA_IMAGE` /
`TYPEARMOR_IMAGE` to existing tags to skip the image builds. `--test` needs the
component, so `WASI_SDK_PATH` must point at a wasi-sdk (>= 24) unless
`target/wasm32-wasip2/release/recfa_verifier_component.wasm` is already built.

What a full run reports:

```
step 1/4   callq sites: 15   indirect: 6   <main>: 1        blocks: 53   call edges: 37
step 2/4   policy F: 100 target entries over 6 indirect call sites
step 3/4   Num of Direct Calls: 5   Num of Filtered DCalls: 2
step 4/4   iCalls: 3   rets: 9   dCalls: 4   skipped dCalls: 2
           program output: acc=299
           prog_instru-re          40 events
           prog_instru-re_folded   24 events
           No events left unprocessed.Progarm is secure     <- upstream's native check
tamper     icall tamper @event 4: site 0x400601 target 0x400595 -> 0x400629
```

`prog_instru-re` is 40 events and the folded evidence is 24: the loop's three
`add` iterations collapse into one compressed event, and the two call sites
csfilter filtered are never recorded at all.

## The two tests

Both drive the **Wasm component** through wasmtime. Upstream's native `check`
also runs, but only as a cross-check inside step 4 — it is never what the tests
assert on.

```bash
bash build.sh --test-only
# equivalently:
cargo test -p recfa-verifier-test -- --ignored custom_e2e
```

```
test custom_e2e::clean_trace_verifies_secure ... ok
test custom_e2e::tampered_trace_is_rejected ... ok
```

**`clean_trace_verifies_secure`** — the real run verifies:

```
verdict: secure   attested: 29   reconstructed: 2   unprocessed: 0
evidence_events: 24   |F|: 15   |M|: 2
```

29 attested addresses from 24 events: verification re-expands the folded loop and
puts back the 2 call sites policy M says the attester skipped
(`events_reconstructed: 2` — the only reason to bother with csfilter). The test
also requires every `reference_values` digest to equal sha256 of the committed
reference file. That check is what gives the verdict meaning: `secure` is only
ever "secure with respect to *these* reference values".

**`tampered_trace_is_rejected`** — the `make-tamper.py` hijack is caught:

```
verdict: indirect-call-violation   attested: 8
error:   indirect-call-violation at 0x400601: target 0x400629 is not permitted
```

`0x400601` is the indirect call in `apply1`, `0x400595` is `square` (what actually
ran), and `0x400629` is `apply3` — a real function that policy F permits at the
other two sites but not at this one. The test first re-derives that from the
artifacts (exactly one event differs from the clean trace; the substituted target
is absent from this site's policy-F set but present in another's), then requires
the component to name that exact edge. Expectations come from the artifacts rather
than hardcoded values, so regenerating the example cannot silently invalidate the
tests.

`make-tamper.py` writes a second file, `.tamper_ret`, which the tests deliberately
do not assert on: it corrupts an arbitrary plain event mid-stream, and on a
24-event trace that lands on a return *source* (`0x4005cb`, `mul`'s `retq`). The
verifier compares return *targets* against the shadow stack and never looks at the
source, so that variant verifies as `secure` — correctly. It is left in
`artifacts/` because the tool produces it; on the long SPEC traces the same
heuristic does hit a target and yields `shadow-stack-violation`.

## Why `prog.c` looks like that

Three indirect call sites passing 1, 2 and 3 arguments, plus five leaf functions
whose addresses are taken through dispatch tables. TypeArmor permits a site to
reach any address-taken function whose consumed-argument count does not exceed
what the site prepares, so the sites get different permitted-target sets — 16
targets at `apply1`'s site, 17 at the other two. (Its estimate of "prepared" is
conservative: it counts argument registers live at the call, so `apply1`'s site
comes out at 3 rather than 1. The ordering is what matters.)

That gap is what `make-tamper.py` needs: it hijacks a site to a function that is
real and permitted *somewhere*, but not there. With a single call site, or sites
that all permit the same targets, it has no candidate and exits with `no indirect
call site occurs in this trace`.

The direct call inside the loop exercises loop folding, and the
`fopen`/`fprintf`/`fclose` tail gives the run an observable side effect
(`acc=299`, in `artifacts/prog.out`).

Two compiler flags are load-bearing:

- **`-no-pie`** keeps every address at 6 hex digits in `0x4xxxxx`. Upstream's
  regexes hardcode `{6}`, so a PIE binary does not work at all.
- **`-g`** is required by the *mutator*, which injects its `fopen` call by
  resolving the DWARF `FILE` type (`appImage->findType("FILE")`). Without debug
  info that lookup returns null and `bin/mutator` **segfaults** inside
  `createAndInsertFopen` — after printing its event-point counts, so it looks like
  it got much further than it did. The shipped SPEC binaries fail identically.
  Not documented upstream.

## Pipeline gotchas this example encodes

Each of these cost a debugging cycle; the scripts now fail loudly on them.

- **binutils must be <= 2.34.** `check.cpp` matches `callq`, `jmpq   *%rax` and
  `retq`; 2.35+ prints those without the `q`, so *no call site is found at all*,
  `|F|` comes out 0, and every trace trivially "passes". `step1` greps for
  `callq`/`retq` and aborts if they are missing — which is also why the
  disassembly is produced in the container and not on your host.
- **Dyninst 9.3.1 cannot fetch its own libdwarf.** Its
  `ExternalProject_Add(LibDwarf)` URL on `www.paradyn.org` 404s. Xenial's
  `libdwarf-dev` is no substitute either: it ships only a non-PIC static archive,
  so linking it into `libdynDwarf.so` fails with `relocation R_X86_64_32S ...
  recompile with -fPIC` — which is what ReCFA-dev's "do not install libdwarf-dev"
  warning is really about. `Dockerfile.typearmor` builds the same libdwarf release
  shared, from the author's own site, and points Dyninst's `find_package` at it.
- **Neither xenial nor bionic is on `old-releases.ubuntu.com`.** Both are EOL but
  still served by the default archive, so do not rewrite `sources.list`; every
  dist 404s if you do.
- **`.filtered` and `.filtered.map` must come from the same csfilter run.** The
  first lists the direct call sites the attester may skip (input to the mutator),
  the second is policy M (input to the verifier). Mismatch them and the verifier
  reconstructs call sites the attester did record, or vice versa.
- **`out/` must exist before the typearmor pass runs**, or TypeArmor segfaults.
  `step2` creates it.

## Reproducibility

Re-running `build.sh` reproduces the evidence byte-for-byte: `prog.asm`,
`prog.dot`, `prog.filtered`, `prog.filtered.map`, `prog_instru-re` and
`prog_instru-re_folded` all keep their digests, because the program is
deterministic and non-PIE.

Two files do churn, harmlessly:

- `binfo.prog` — same 100 entries every run, but the patched pass iterates
  unordered containers, so line *order* varies. Sorted output is identical.
- `prog_instru` — Dyninst's rewriter does not emit a reproducible binary.

The tests hash the committed files, so this churn cannot break them.

## Files

```
prog.c                     the attested program
build.sh                   one-shot: artifacts + tests
attester/
  Dockerfile.recfa         Ubuntu 18.04 + Dyninst 10.1 + binutils 2.30
  Dockerfile.typearmor     Ubuntu 16.04 + Dyninst 9.3.1 + patched TypeArmor
  step1-compile-cfg.sh     compile, objdump, preCFG
  step2-policy-f.sh        patched TypeArmor -> binfo.prog
  step4-instrument-run.sh  mutator, the attested run, folding, native cross-check
artifacts/                 everything the two tests consume (committed)
```

Step 3 (csfilter) is one `java -jar` and lives in `build.sh`.

`artifacts/` also keeps `prog` and `prog_instru`, so the disassembly can be
re-derived from the exact bytes that were analysed and the attested execution can
be replayed without rebuilding any of the toolchains, plus `typearmor.log` and
`mutator.log` as the audit trail of the two analysis passes.
