# Real ReCFA evidence — bzip2_base.gcc_O0

Genuine attester output, not synthetic. Provenance:

| file | origin |
|---|---|
| `bzip2_base.gcc_O0.asm` | `objdump -d` on the binary shipped in upstream `spec_gcc/O0/`, binutils 2.30 |
| `bzip2_base.gcc_O0.dot` | `bin/preCFG` (Dyninst 10.1 ParseAPI) on the same binary |
| `binfo.bzip2_base.gcc_O0` | upstream `policy/F/`, patched-typearmor output |
| `bzip2_base.gcc_O0.filtered.map` | upstream `policy/M/`, csfilter output |
| `bzip2_base.gcc_O0_instru-re_folded` | authors' `re-gcc.zip`, folded with `./compress.sh gcc` |

`num_executions` for bzip2 is **2** (from upstream `verify.sh`).

Expected result: `secure`, `events_attested` 3615494, `events_reconstructed` 3282,
`|M|` 134, `|F|` 460, `main` 0x401e5e, `main_ret` 0x4021b3.

The `.gitignore` here keeps the multi-megabyte artifacts out of the repo; see
`../../ATTESTER_SETUP.md` to regenerate them, and `../../tools/make-tamper.py` to
derive the negative cases.
