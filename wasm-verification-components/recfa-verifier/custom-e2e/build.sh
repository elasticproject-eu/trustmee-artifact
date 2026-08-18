#!/usr/bin/env bash
# Build the whole ReCFA end-to-end example from prog.c: real static
# instrumentation, a real attested execution, real reference values, then the two
# end-to-end tests against the **Wasm component** (never the native verifier).
#
#   bash build.sh              # regenerate every artifact in artifacts/
#   bash build.sh --test       # ... and run the two e2e tests
#   bash build.sh --test-only  # only run the tests, against committed artifacts
#
# What runs where:
#   recfa-dyninst    (Ubuntu 18.04 + Dyninst 10.1 + binutils 2.30)
#                    compile, objdump, preCFG, mutator, the run, folding
#   recfa-typearmor  (Ubuntu 16.04 + Dyninst 9.3.1 + patched typearmor)
#                    policy F
#   host             csfilter (a jar), make-tamper.py, the Wasm component
#
# Environment overrides:
#   RECFA_UPSTREAM    upstream ReCFA checkout (default: ./.upstream/ReCFA, cloned if absent)
#   RECFA_IMAGE       attester image tag      (default: recfa-dyninst)
#   TYPEARMOR_IMAGE   typearmor image tag     (default: recfa-typearmor)
#   WASI_SDK_PATH     needed by --test to build the component
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ART=$HERE/artifacts
WVC=$(cd "$HERE/../.." && pwd)                       # wasm-verification-components
UPSTREAM=${RECFA_UPSTREAM:-$HERE/.upstream/ReCFA}
IMG_RECFA=${RECFA_IMAGE:-recfa-dyninst}
IMG_TA=${TYPEARMOR_IMAGE:-recfa-typearmor}
COMPONENT=$WVC/target/wasm32-wasip2/release/recfa_verifier_component.wasm

DO_BUILD=1
DO_TEST=0
case "${1:-}" in
  --test)      DO_TEST=1 ;;
  --test-only) DO_TEST=1; DO_BUILD=0 ;;
  "")          ;;
  *)           echo "usage: $0 [--test|--test-only]" >&2; exit 2 ;;
esac

say() { printf '\n=== %s\n' "$*"; }

# Containers run as root, so anything they create in artifacts/ would land in the
# repo owned by root. Hand it back after every container step. (Done in a
# container rather than with plain chown because the files are root-owned by
# then; the attester image is reused so this needs no extra image.)
fix_perms() {
  docker run --rm -v "$ART:/t" "$IMG_RECFA" chown -R "$(id -u):$(id -g)" /t
}

in_recfa() {
  docker run --rm \
    -v "$UPSTREAM:/work" -v "$HERE:/example:ro" -v "$ART:/out" \
    "$IMG_RECFA" bash "/example/attester/$1"
  fix_perms
}

in_typearmor() {
  docker run --rm \
    -v "$HERE:/example:ro" -v "$ART:/out" \
    "$IMG_TA" bash "/example/attester/$1"
  fix_perms
}

if [ "$DO_BUILD" = 1 ]; then
  say "prerequisites"
  command -v docker  >/dev/null || { echo "docker is required"; exit 1; }
  command -v java    >/dev/null || { echo "java is required (csfilter is a jar)"; exit 1; }
  command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
  docker info >/dev/null 2>&1   || { echo "cannot talk to the docker daemon"; exit 1; }
  echo "ok: docker, java $(java -version 2>&1 | head -1 | awk '{print $3}'), $(python3 --version)"

  say "upstream ReCFA checkout"
  if [ ! -d "$UPSTREAM/bin" ]; then
    echo "cloning upstream ReCFA into $UPSTREAM (~185 MB)"
    mkdir -p "$(dirname "$UPSTREAM")"
    git clone --depth 1 https://github.com/suncongxd/ReCFA.git "$UPSTREAM"
  fi
  for tool in bin/preCFG bin/mutator bin/folding bin/check bin/csfilter.jar lib/libfold.so; do
    test -e "$UPSTREAM/$tool" || { echo "FATAL: $UPSTREAM/$tool missing"; exit 1; }
  done
  echo "ok: $UPSTREAM"

  say "container images"
  for spec in "$IMG_RECFA:Dockerfile.recfa" "$IMG_TA:Dockerfile.typearmor"; do
    img=${spec%%:*}; dockerfile=${spec#*:}
    if docker image inspect "$img" >/dev/null 2>&1; then
      echo "ok: $img (already built)"
    else
      echo "building $img from $dockerfile — this takes tens of minutes (Dyninst from source)"
      docker build -f "$HERE/attester/$dockerfile" -t "$img" "$HERE/attester"
    fi
  done

  mkdir -p "$ART"

  say "step 1/4 — compile prog.c, disassemble, build the CFG   [recfa-dyninst]"
  in_recfa step1-compile-cfg.sh

  say "step 2/4 — policy F with the patched typearmor pass      [recfa-typearmor]"
  in_typearmor step2-policy-f.sh

  say "step 3/4 — policy M with csfilter                        [host, java]"
  # csfilter emits two files: the list of direct call sites the attester may skip
  # (prog.filtered, consumed by the mutator in step 4) and the mapping the
  # verifier uses to re-insert them (prog.filtered.map == policy M).
  ( cd "$ART" && java -jar "$UPSTREAM/bin/csfilter.jar" prog.dot prog.asm prog.filtered ) \
    | sed 's/^/   /'
  printf "   filtered direct call sites: %s   policy M entries: %s\n" \
    "$(wc -l < "$ART/prog.filtered")" "$(wc -l < "$ART/prog.filtered.map")"

  say "step 4/4 — instrument, run, fold                          [recfa-dyninst]"
  in_recfa step4-instrument-run.sh

  say "tamper — derive hijacked traces with tools/make-tamper.py [host]"
  python3 "$WVC/recfa-verifier/tools/make-tamper.py" \
    "$ART/prog_instru-re_folded" "$ART/binfo.prog" | sed 's/^/   /'

  say "artifacts"
  ( cd "$ART" && ls -la | sed 's/^/   /' )
fi

if [ "$DO_TEST" = 1 ]; then
  say "end-to-end tests — Wasm component via wasmtime"
  if [ ! -f "$COMPONENT" ]; then
    echo "building the component (needs WASI_SDK_PATH, wasi-sdk >= 24)"
    : "${WASI_SDK_PATH:?set WASI_SDK_PATH to a wasi-sdk with bin/clang++}"
    ( cd "$WVC" && cargo build -p recfa-verifier-component --release --target wasm32-wasip2 )
  fi
  echo "component: $COMPONENT"
  # The two tests live in recfa-verifier-test so they run like any other test in
  # the workspace; they load the component and drive it through wasmtime.
  ( cd "$WVC" && cargo test -p recfa-verifier-test --  --ignored --nocapture custom_e2e )
fi
