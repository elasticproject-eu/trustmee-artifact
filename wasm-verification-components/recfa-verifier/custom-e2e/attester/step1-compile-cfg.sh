#!/bin/bash
# Step 1 of the attester pipeline — runs INSIDE the recfa-dyninst container.
#   /work = upstream ReCFA checkout, /example = custom-e2e (ro), /out = artifacts
#
# Compiles prog.c and produces the two reference values that describe the binary:
# its disassembly and its CFG.
set -euo pipefail
cd /out

echo "-- toolchain"
gcc --version | head -1
objdump --version | head -1     # must be <= 2.34, see Dockerfile.recfa

echo "-- compile (non-PIE, with DWARF)"
gcc -O0 -no-pie -g /example/prog.c -o prog

echo "-- disassembly (objdump -d)"
objdump -d prog > prog.asm
printf "   callq sites: %s   indirect: %s   <main>: %s\n" \
  "$(grep -c 'callq' prog.asm)" \
  "$(grep -c 'callq  \*' prog.asm)" \
  "$(grep -c '<main>:' prog.asm)"

echo "-- CFG (bin/preCFG, Dyninst ParseAPI)"
/work/bin/preCFG prog > prog.dot
printf "   blocks: %s   call edges: %s\n" \
  "$(grep -cE '^\s*"\[[0-9a-f]{6},[0-9a-f]{6}' prog.dot || true)" \
  "$(grep -c 'color=blue' prog.dot || true)"

# Fail loudly on the silent-failure mode described in ATTESTER_SETUP.md: a modern
# objdump prints `call`/`ret` without the `q`, so no call site is ever matched,
# |F| comes out 0, and every trace trivially "passes".
grep -q 'callq' prog.asm || { echo "FATAL: no 'callq' in prog.asm — objdump too new"; exit 1; }
grep -q 'retq'  prog.asm || { echo "FATAL: no 'retq' in prog.asm — objdump too new";  exit 1; }
