#!/bin/bash
# Step 2 of the attester pipeline — runs INSIDE the recfa-typearmor container.
#   /out = custom-e2e/artifacts (must already contain the compiled `prog`)
#
# Produces policy F with the patched TypeArmor static pass. This is upstream's
# `run-ta-static.sh` with two deviations, both mechanical:
#   - no `sudo`: we are already root in the container
#   - explicit paths, because run-ta-static.sh derives them from `pwd` and insists
#     on being started from a subdirectory of the typearmor checkout
set -euo pipefail

test -f /out/prog || { echo "FATAL: /out/prog missing — run step1 first"; exit 1; }

# The pass writes $BINFO.<exe>, and out/ must exist or TypeArmor segfaults.
mkdir -p /opt/typearmor/out
export BINFO=/opt/typearmor/out/binfo
rm -f "$BINFO".*

# Analyse a copy inside the checkout, so the emitted name is binfo.prog.
cd /opt/typearmor/server-bins
cp /out/prog ./prog

DI=$DYNINST_ROOT/install
echo "-- patched typearmor static pass (Dyninst $(basename "$DYNINST_ROOT" | sed 's/dyninst-//'))"
DYNINSTAPI_RT_LIB=$DI/lib/libdyninstAPI_RT.so \
LD_LIBRARY_PATH=$DI/lib:${LD_LIBRARY_PATH:-} \
  /opt/typearmor/bin/di-opt \
    -load=/opt/typearmor/bin/fcfi_pass.di -fcfi_pass \
    -binfo="$BINFO" -args "$PWD/prog" 2> /out/typearmor.log

test -s "$BINFO".prog || { echo "FATAL: no policy F produced; see artifacts/typearmor.log"; tail -20 /out/typearmor.log; exit 1; }
cp "$BINFO".prog /out/binfo.prog

echo "-- policy F: $(grep -c 'Indirectstar' /out/binfo.prog) target entries over $(grep -o 'Indirectstar0x[0-9a-f]*' /out/binfo.prog | sort -u | wc -l) indirect call sites"
grep 'Indirectstar' /out/binfo.prog | sed 's/^/   /'
