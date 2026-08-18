#!/bin/bash
# Step 4 of the attester pipeline — runs INSIDE the recfa-dyninst container.
#   /work = upstream ReCFA checkout, /out = custom-e2e/artifacts
#
# Statically instruments the binary, runs it (this is the attested execution),
# and folds the recorded event stream into the evidence the verifier consumes.
# Step 3 (csfilter, on the host) must have produced prog.filtered first.
set -euo pipefail
cd /out

test -f prog          || { echo "FATAL: prog missing — run step1 first";     exit 1; }
test -f prog.filtered || { echo "FATAL: prog.filtered missing — run step3";  exit 1; }

echo "-- instrument (bin/mutator, Dyninst binary rewriting)"
rm -f prog_instru prog_instru-re prog_instru-re_folded prog.out
# `prog.filtered` is csfilter's list of direct call sites the attester may skip;
# an empty list simply means nothing is skipped. The mutator segfaults with no
# diagnostic if the mutatee lacks DWARF (it resolves the `FILE` type to inject
# its fopen call), which is why step1 compiles with -g.
/work/bin/mutator prog prog_instru prog.filtered > mutator.log 2>&1 \
  || { echo "FATAL: mutator failed"; tail -20 mutator.log; exit 1; }
grep -E "Num of (iJmps|iCalls|rets|dCalls|skipped dCalls)" mutator.log | sed 's/^/   /'

echo "-- run the instrumented binary (the attested execution)"
export LD_LIBRARY_PATH=/work/lib:${LD_LIBRARY_PATH:-}
./prog_instru
echo "   program output: $(cat prog.out)"
test -s prog_instru-re || { echo "FATAL: no events recorded"; exit 1; }

echo "-- fold (bin/folding)"
/work/bin/folding prog_instru-re
test -s prog_instru-re_folded || { echo "FATAL: folding produced nothing"; exit 1; }

python3 - <<'PY'
import struct
for name in ("prog_instru-re", "prog_instru-re_folded"):
    with open(name, "rb") as fh:
        data = fh.read()
    events = list(struct.unpack("<%dI" % (len(data) // 4), data))
    print("   %-22s %3d events" % (name, len(events)))
PY

echo "-- cross-check with upstream bin/check (native; the component is verified separately)"
/work/bin/check prog.asm prog.dot binfo.prog prog.filtered.map prog_instru-re_folded 1 gcc \
  2>&1 | grep -E "\|M\||secure|Indirect|unprocessed" | sed 's/^/   /'
