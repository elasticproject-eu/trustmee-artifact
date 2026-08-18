#!/usr/bin/env python3
"""
Generate a minimal, fully-understood ReCFA fixture.

Mirrors the exact input formats that upstream src/verifier/check.cpp parses:
  .asm  -> objdump -d output, binutils <=2.34 mnemonics (callq/jmpq/retq)
  .dot  -> src/preCFG/preCFG.cc output  ("[start,last";  and  "src" -> "trg" [color=blue])
  F     -> patched-typearmor binfo      (Indirectstar0x<site>  <n> Indirectend0x<target>)
  M     -> csfilter map                 (<target> [<skipped-call-site>])
  trace -> little-endian u32 control-flow events

Program layout (all addresses 6 hex digits, as the regexes require):

  401000 <main>
    401010  callq  401100 <foo>      ; direct call,   Pair=401015
    401020  callq  *%rax             ; indirect call, Pair=401025
    401030  jmpq   *%rax             ; indirect jump
    401050  retq                     ; -> Ret
  401100 <foo>
    401110  retq
  401200 <bar>
    401210  retq
"""
import struct, sys, os

MAIN, MAIN_RET = 0x401000, 0x401050
DCALL, DCALL_PAIR, FOO = 0x401010, 0x401015, 0x401100
ICALL, ICALL_PAIR, BAR = 0x401020, 0x401025, 0x401200
IJMP, IJMP_TRG = 0x401030, 0x401040
FOO_RET, BAR_RET = 0x401110, 0x401210

END = 0x7FFFEEEE
NEWRUN = 0xFFFFEEEE
MSB = 0x80000000


def asm() -> str:
    # objdump-style. mnemonic field is padded to 7 chars: "callq  " / "jmpq   " / "retq   "
    L = []
    L.append("")
    L.append("prog:     file format elf64-x86-64")
    L.append("")
    L.append("")
    L.append("Disassembly of section .text:")
    L.append("")
    L.append("0000000000401000 <main>:")
    L.append("  401000:\t55                   \tpush   %rbp")
    L.append("  401010:\te8 eb 00 00 00       \tcallq  401100 <foo>")
    L.append("  401015:\t48 89 e5             \tmov    %rsp,%rbp")
    L.append("  401020:\tff d0                \tcallq  *%rax")
    L.append("  401025:\t48 89 e5             \tmov    %rsp,%rbp")
    L.append("  401030:\tff e0                \tjmpq   *%rax")
    L.append("  401040:\t48 89 e5             \tmov    %rsp,%rbp")
    L.append("  401050:\tc3                   \tretq   ")
    L.append("")
    L.append("0000000000401100 <foo>:")
    L.append("  401100:\t55                   \tpush   %rbp")
    L.append("  401110:\tc3                   \tretq   ")
    L.append("")
    L.append("0000000000401200 <bar>:")
    L.append("  401200:\t55                   \tpush   %rbp")
    L.append("  401210:\tc3                   \tretq   ")
    L.append("")
    return "\n".join(L) + "\n"


def dot() -> str:
    """preCFG.cc emits: node lines  "[start,last";   then edges  "src" -> "trg" [color=blue].
    readDyninst maps Block[start]=last, then for edge src->trg looks up b=Block[src]."""
    L = ["digraph G {"]
    # cluster for main
    L.append("\t subgraph cluster_0 { ")
    L.append('\t\t label="main"; ')
    L.append("\t\t color=blue;")
    L.append('\t\t"401000" [shape=box]')
    L.append('\t\t"401000" [label = "main\\n401000"];')
    L.append('\t\t"[401000,401010";')   # block ending at the direct call
    L.append('\t\t"[401015,401020";')   # block ending at the indirect call
    L.append('\t\t"[401025,401030";')   # block ending at the indirect jump
    L.append("\t}")
    # call edge: gives proMap[401010].Jump = {401100}  (needed by policy M / FtoN)
    L.append('\t"401000" -> "401100" [color=blue]')
    # indirect jump edge: creates proMap[401030] Type=2 with Jump={401040}
    L.append('\t"401025" -> "401040"')
    L.append("")
    # cluster for foo
    L.append("\t subgraph cluster_1 { ")
    L.append('\t\t label="foo"; ')
    L.append("\t\t color=blue;")
    L.append('\t\t"401100" [shape=box]')
    L.append('\t\t"[401100,401110";')
    L.append("\t}")
    L.append("")
    L.append("}")
    return "\n".join(L) + "\n"


def policy_f() -> str:
    """patched typearmor: the indirect call at 401020 may target bar (401200)."""
    L = []
    L.append("Object: prog")
    L.append("Functions: 3")
    L.append("")
    L.append("[icall-args]")
    L.append("Indirectstar0x%06x  6 Indirectend0x%06x 0 " % (ICALL, BAR))
    L.append("")
    L.append("[done]")
    return "\n".join(L) + "\n"


def policy_m(enabled: bool) -> str:
    """csfilter map: '<For> [<b>]' -> ForNext[For]=b.
    FtoN(For) then requires proMap[b].Jump to have exactly one element."""
    if not enabled:
        return ""
    # After control reaches 401200 (bar), a skipped direct call at 401010 is re-inserted.
    return "%06x [%06x]\n" % (BAR, DCALL)


def trace(events) -> bytes:
    return b"".join(struct.pack("<I", e) for e in events)


# --- event sequences -------------------------------------------------------

def ev_pass_simple():
    """direct call -> foo returns -> main returns -> end"""
    return [DCALL, FOO, FOO_RET, DCALL_PAIR, MAIN_RET, END]


def ev_pass_compressed():
    """same, but the direct call uses the MSB-compressed single-event encoding"""
    return [DCALL | MSB, FOO_RET, DCALL_PAIR, MAIN_RET, END]


def ev_pass_icall():
    """direct call, then indirect call to bar (allowed by policy F), then returns"""
    return [DCALL, FOO, FOO_RET, DCALL_PAIR,
            ICALL, BAR, BAR_RET, ICALL_PAIR,
            MAIN_RET, END]


def ev_pass_ijmp():
    """indirect jump to a target present in the .dot"""
    return [IJMP, IJMP_TRG, MAIN_RET, END]


def ev_fail_icall():
    """indirect call to a target NOT in policy F -> 'Indirect Call'"""
    return [ICALL, FOO, MAIN_RET, END]


def ev_fail_ijmp():
    """indirect jump to a target NOT in the .dot -> 'Indirect Jump'"""
    return [IJMP, BAR, MAIN_RET, END]


def ev_fail_shadow():
    """foo returns to a bogus address -> shadow-stack violation"""
    return [DCALL, FOO, FOO_RET, 0x401bad, MAIN_RET, END]


CASES = {
    "pass_simple":     (ev_pass_simple,     False),
    "pass_compressed": (ev_pass_compressed, False),
    "pass_icall":      (ev_pass_icall,      False),
    "pass_ijmp":       (ev_pass_ijmp,       False),
    "fail_icall":      (ev_fail_icall,      False),
    "fail_ijmp":       (ev_fail_ijmp,       False),
    "fail_shadow":     (ev_fail_shadow,     False),
    "pass_policy_m":   (ev_pass_icall,      True),
}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fixture"
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "prog.asm"), "w") as f:
        f.write(asm())
    with open(os.path.join(out, "prog.dot"), "w") as f:
        f.write(dot())
    with open(os.path.join(out, "binfo.prog"), "w") as f:
        f.write(policy_f())
    for name, (evfn, m_enabled) in CASES.items():
        with open(os.path.join(out, "%s.trace" % name), "wb") as f:
            f.write(trace(evfn()))
        with open(os.path.join(out, "%s.map" % name), "w") as f:
            f.write(policy_m(m_enabled))
    print("wrote fixture to %s/ : %d cases" % (out, len(CASES)))
    for name, (evfn, m) in sorted(CASES.items()):
        print("  %-16s %2d events  policy_M=%s" % (name, len(evfn()), m))


if __name__ == "__main__":
    main()
