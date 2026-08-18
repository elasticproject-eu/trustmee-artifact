#!/usr/bin/env python3
"""
Generate vendor/check.cpp from upstream ReCFA's src/verifier/check.cpp.

Upstream:  https://github.com/suncongxd/ReCFA  (ACSAC'21)
           src/verifier/check.cpp
           sha256 9f72861d5f860ecaf574eca63c038e93b163cd20fb6df93e11b4da1740c8beef

Usage:  python3 patch-upstream.py /path/to/ReCFA/src/verifier/check.cpp

Every edit below is applied by exact string match with an asserted occurrence
count, so the patch either applies cleanly to that exact upstream revision or
fails loudly. The verification algorithm itself (readAsmFile / readDyninst /
readTypeAmror / readForToNext / FtoN / verifi / verifiSecond bodies) is NOT
touched: the edits are confined to

  (a) PORTABILITY  - includes libc++ does not pull in transitively; drop unused
                     <thread>; read inputs from an in-memory VFS instead of the
                     filesystem, so the component needs no preopened dir.
  (b) NO-TRAP      - the four exit(-1) sites become a fatal flag + early return,
                     because a Wasm trap is a host error, not a verdict.
  (c) VERDICT      - capture which verdict branch was taken, instead of making
                     the caller scrape stdout.
  (d) MEMORY-SAFETY- upstream assigns a dangling `(m.str(N)).c_str()` to `char *c`
                     and reads it in the NEXT statement (22 sites, use-after-free).
                     Fixed by changing the 10 declarations of `c` to an owning
                     holder. Also guards two `proMap.find(...)->second` uses that
                     dereference end() on attacker-controlled evidence.
"""
import hashlib
import os
import sys

UPSTREAM_SHA256 = "9f72861d5f860ecaf574eca63c038e93b163cd20fb6df93e11b4da1740c8beef"

TAG = "/* RECFA-PORT */"

SHIM = r'''
/* ==== RECFA-PORT: additive support code, no upstream logic changed ======== */
#include "recfa_entry.h"
#include <cstddef>
#include <cstring>

/* Inputs are handed to us as memory buffers by the Wasm component shell, keyed
   by the same "filenames" that are passed down as argv. This lets every upstream
   parser keep its `char *file` signature and its exact parsing code, while the
   component needs no filesystem access at all. */
static std::map<std::string, std::string> g_vfs;

static int g_fatal = 0;                 /* RECFA_VERDICT_* once a fatal path hit */
static int g_verdict = RECFA_VERDICT_UNKNOWN;
static long long g_unprocessed = 0;     /* sto->size() at a shadow-stack failure */
static unsigned int g_last_site = 0;    /* transfer instruction being checked     */
static unsigned int g_bad_target = 0;   /* the target that violated the policy    */
static unsigned int g_main_addr = 0, g_ret_addr = 0;

extern "C" void recfa_vfs_put(const char *name, const unsigned char *data,
                              unsigned long len) {
  g_vfs[std::string(name)] = std::string((const char *)data, (size_t)len);
}
extern "C" void recfa_vfs_clear(void) { g_vfs.clear(); }

/* Drop-in replacement for `fstream f(path)`: a non-copying istream over the VFS
   entry, so a 100 MB .asm is not duplicated in linear memory. */
struct RecfaIn : std::istream {
  struct Buf : std::streambuf {
    Buf(const char *p, size_t n) {
      setg(const_cast<char *>(p), const_cast<char *>(p), const_cast<char *>(p) + n);
    }
  };
  Buf buf_;
  explicit RecfaIn(const char *name)
      : std::istream(NULL),
        buf_(g_vfs.count(name) ? g_vfs[name].data() : "",
             g_vfs.count(name) ? g_vfs[name].size() : 0) {
    this->rdbuf(&buf_);
  }
};

/* Drop-in replacement for `fopen(path, "r")` on the event stream. */
static FILE *recfa_fopen(const char *name) {
  std::map<std::string, std::string>::iterator it = g_vfs.find(name);
  if (it == g_vfs.end())
    return NULL;
  return fmemopen(const_cast<char *>(it->second.data()), it->second.size(), "rb");
}

/* Owning stand-in for upstream's `char *c`. Upstream does
     c = (char *)(m.str(1)).c_str();
     b = strtoll(c, NULL, 16);
   where the std::string temporary dies at the end of the first statement, so the
   second reads freed memory. Assigning through this holder copies the bytes while
   the temporary is still alive; every use site stays character-for-character the
   same because of the implicit conversion back to char *. */
struct RecfaStr {
  std::string s;
  RecfaStr() {}
  RecfaStr(const char *p) { s = (p ? p : ""); }
  RecfaStr &operator=(const char *p) {
    s = (p ? p : "");
    return *this;
  }
  operator char *() { return const_cast<char *>(s.c_str()); }
};
/* ======================================================================== */
'''

# Inserted after proMap/ForNext are declared, since it needs `newblock`.
DIRECT_TARGET = r'''
/* RECFA-PORT
   Upstream writes `proMap.find(buffer)->second.directTarget` with no check that
   the lookup succeeded, dereferencing end() when it fails. That is not merely an
   adversarial edge case: it happens on every well-formed trace. Once `executetime`
   runs have been consumed, the trailing 0xffffeeee run marker falls through to the
   compressed-direct-call branch, and stripping its high bit yields 0x7fffeeee --
   the end-of-program sentinel, which is deliberately not a call site. verifi()
   relies on that sentinel to terminate successfully, so this lookup has to fail
   benignly rather than be rejected. Returning a defined 0 preserves upstream's
   control flow exactly while removing the indeterminate read; the pushed target is
   never examined, because verifi() stops at the sentinel ahead of it. */
static int recfa_direct_target(int site) {
  map<int, newblock>::iterator it = proMap.find(site);
  return (it == proMap.end()) ? 0 : it->second.directTarget;
}
'''

ENTRY = r'''
/* ==== RECFA-PORT: C entry point used by the Wasm component shell ========= */
extern "C" int recfa_verify(const char *asm_name, const char *dot_name,
                            const char *f_name, const char *m_name,
                            const char *trace_name, int num_executions,
                            const char *compiler_type, recfa_result *out) {
  if (!out)
    return -1;

  /* Reset every upstream global so repeated calls are deterministic. */
  proMap.clear();
  ForNext.clear();
  success = 0;
  total = 0;
  timeRead = 0;
  timeTotal = 0;
  executetime = 0;
  st = 0;
  count1 = 0;
  Maintotal = 1;
  g_fatal = 0;
  g_verdict = RECFA_VERDICT_UNKNOWN;
  g_unprocessed = 0;
  g_last_site = 0;
  g_bad_target = 0;
  g_main_addr = 0;
  g_ret_addr = 0;

  char numbuf[32];
  snprintf(numbuf, sizeof(numbuf), "%d", num_executions);

  char *argv[8];
  argv[0] = const_cast<char *>("check");
  argv[1] = const_cast<char *>(asm_name);
  argv[2] = const_cast<char *>(dot_name);
  argv[3] = const_cast<char *>(f_name);
  argv[4] = const_cast<char *>(m_name);
  argv[5] = const_cast<char *>(trace_name);
  argv[6] = numbuf;
  argv[7] = const_cast<char *>(compiler_type);

  int rc = recfa_check_main(8, argv);

  memset(out, 0, sizeof(*out));
  out->verdict = g_fatal ? g_fatal : g_verdict;
  out->events_attested = (int64_t)total;
  out->events_unprocessed = (int64_t)g_unprocessed;
  out->events_reconstructed = (int64_t)success;
  out->policy_m_entries = (uint32_t)ForNext.size();
  out->policy_f_entries = (uint32_t)proMap.size();
  out->violation_site = g_last_site;
  out->violation_target = g_bad_target;
  out->main_addr = g_main_addr;
  out->main_ret_addr = g_ret_addr;
  return rc;
}
/* ======================================================================== */
'''

# (old, new, expected_count)
EDITS = [
    # ---- (a) portability: includes libc++ does not pull in transitively -----
    ("#include <bitset>\n",
     "#include <bitset>\n#include <cstdint>\n#include <map>\n#include <stack>\n",
     1),
    # <thread> is unused and drags in a threading impl the sandbox does not have
    ("#include <thread>\n", "", 1),

    # ---- shim block right after `using namespace std;` ---------------------
    ("using namespace std;\n", "using namespace std;\n" + SHIM, 1),

    # ---- helper that needs `newblock`, so it goes after the globals --------
    ("map<int, newblock> proMap;\nmap<int, int> ForNext;\n",
     "map<int, newblock> proMap;\nmap<int, int> ForNext;\n" + DIRECT_TARGET, 1),

    # ---- (a) read inputs from the in-memory VFS ---------------------------
    ("  fstream f(file);", "  RecfaIn f(file);   " + TAG, 4),
    ("  fstream f1(file);", "  RecfaIn f1(file);   " + TAG, 1),
    ('  in = fopen(file, "r");', "  in = recfa_fopen(file);   " + TAG, 1),

    # ---- (d) memory safety: owning holder for the 22 dangling c_str() uses --
    # newline-anchored so the 6-space and 2-space declarations cannot alias
    ("\n      char *c;\n", "\n      RecfaStr c;   " + TAG + "\n", 6),
    ("\n  char *c;\n", "\n  RecfaStr c;   " + TAG + "\n", 1),
    ("      char *c = (char *)m.str(1).c_str();",
     "      RecfaStr c = (char *)m.str(1).c_str();   " + TAG, 3),

    # ---- (b) no-trap: the four exit(-1) sites ------------------------------
    # FtoN: policy M points at a block the CFG does not describe
    ('      cout << "dyninst fail  " << proMap.find(b)->second.Jump.size() << endl;\n'
     "      exit(-1);\n",
     '      cout << "dyninst fail  " << proMap.find(b)->second.Jump.size() << endl;\n'
     "      g_fatal = RECFA_VERDICT_DYNINST;   " + TAG + "\n"
     "      return;\n",
     1),
    # verifi: indirect call target not permitted by policy F
    ('          cout << "Indirect Call" << endl;\n          exit(-1);\n',
     '          cout << "Indirect Call" << endl;\n'
     "          g_fatal = RECFA_VERDICT_ICALL;   " + TAG + "\n"
     "          g_bad_target = (unsigned int)buffer;\n"
     "          return true;\n",
     1),
    # verifi: indirect jump target not in the CFG
    ('          cout << "Indirect Jump" << endl;\n          exit(-1);\n',
     '          cout << "Indirect Jump" << endl;\n'
     "          g_fatal = RECFA_VERDICT_IJMP;   " + TAG + "\n"
     "          g_bad_target = (unsigned int)buffer;\n"
     "          return true;\n",
     1),
    # readTypeAmror: policy F names a call site absent from the disassembly
    ('        cout << "Policy F read error." << endl;\n        exit(-1);\n',
     '        cout << "Policy F read error." << endl;\n'
     "        g_fatal = RECFA_VERDICT_POLICY_F;   " + TAG + "\n"
     "        return;\n",
     1),

    # ---- (c) verdict capture ---------------------------------------------
    # the two "secure" exits inside verifi()
    ('          cout << total << "events sucess" << endl;\n'
     '          cout << "No events left unprocessed.Progarm is secure" << endl;\n'
     "          return true;\n",
     '          cout << total << "events sucess" << endl;\n'
     '          cout << "No events left unprocessed.Progarm is secure" << endl;\n'
     "          g_verdict = RECFA_VERDICT_SECURE;   " + TAG + "\n"
     "          return true;\n",
     2),
    # the "secure" exit in readReceive()
    ("  if (!veri) {\n"
     '    cout << total << "events sucess" << endl;\n'
     '    cout << "No events left unprocessed.Progarm is secure" << endl;\n'
     "  }\n",
     "  if (!veri) {\n"
     '    cout << total << "events sucess" << endl;\n'
     '    cout << "No events left unprocessed.Progarm is secure" << endl;\n'
     "    g_verdict = RECFA_VERDICT_SECURE;   " + TAG + "\n"
     "  }\n",
     1),
    # the shadow-stack failure exit
    ("        if (shadow->empty() && !flag) {\n"
     '          printf("fail,%ld events unprocessed\\n", sto->size());\n'
     "          return true;\n",
     "        if (shadow->empty() && !flag) {\n"
     '          printf("fail,%ld events unprocessed\\n", sto->size());\n'
     "          g_verdict = RECFA_VERDICT_SHADOW;   " + TAG + "\n"
     "          g_unprocessed = (long long)sto->size();\n"
     "          return true;\n",
     1),

    # ---- (b)/(d) stop promptly once fatal; record the site being checked ----
    ("void FtoN(queue<int> *sto, int For) {\n",
     "void FtoN(queue<int> *sto, int For) {\n"
     "  if (g_fatal)   " + TAG + "\n    return;\n", 1),
    # guard upstream's unchecked proMap.find(b)->second in FtoN
    ("  if (ForNext.count(For)) {\n    int b = ForNext.find(For)->second;\n",
     "  if (ForNext.count(For)) {\n    int b = ForNext.find(For)->second;\n"
     "    if (proMap.find(b) == proMap.end()) {   " + TAG + "\n"
     "      g_fatal = RECFA_VERDICT_DYNINST;\n      return;\n    }\n", 1),
    ("  while (!sto->empty()) {\n    buffer = sto->front();\n",
     "  while (!sto->empty()) {\n"
     "    if (g_fatal)   " + TAG + "\n      return true;\n"
     "    buffer = sto->front();\n", 1),
    ("    if (proMap.count(buffer)) {\n      newblock block = proMap.find(buffer)->second;\n",
     "    if (proMap.count(buffer)) {\n"
     "      g_last_site = (unsigned int)buffer;   " + TAG + "\n"
     "      newblock block = proMap.find(buffer)->second;\n", 1),

    # ---- (d) never dereference proMap.end() (fires on well-formed traces) ---
    # readReceive
    ("      sto.push(buffer);\n"
     "      sto.push(proMap.find(buffer)->second.directTarget);\n"
     '      // printf("%xhhhhhhhhhhh\\n",proMap.find(buffer)->second.directTarget);\n'
     "      buffer = proMap.find(buffer)->second.directTarget;\n",
     "      sto.push(buffer);\n"
     "      sto.push(recfa_direct_target(buffer));   " + TAG + "\n"
     '      // printf("%xhhhhhhhhhhh\\n",proMap.find(buffer)->second.directTarget);\n'
     "      buffer = recfa_direct_target(buffer);   " + TAG + "\n",
     1),
    # verifiSecond, on the streaming path
    ("      sto->push(buffer);\n"
     "      sto->push(proMap.find(buffer)->second.directTarget);\n"
     '      // printf("%xhhhhhhhhhhh\\n",proMap.find(buffer)->second.directTarget);\n'
     "      buffer = proMap.find(buffer)->second.directTarget;\n",
     "      sto->push(buffer);\n"
     "      sto->push(recfa_direct_target(buffer));   " + TAG + "\n"
     '      // printf("%xhhhhhhhhhhh\\n",proMap.find(buffer)->second.directTarget);\n'
     "      buffer = recfa_direct_target(buffer);   " + TAG + "\n",
     1),
    # stop the streaming reader once fatal
    ("  while (rbyte = fread(&buffer, 4, 1, in) == 1) {\n"
     '    // if((buffer==0xffffeeee)&&Maintotal<executetime)\n',
     "  while (rbyte = fread(&buffer, 4, 1, in) == 1) {\n"
     "    if (g_fatal)   " + TAG + "\n      return;\n"
     '    // if((buffer==0xffffeeee)&&Maintotal<executetime)\n', 1),

    # ---- (c) expose main/ret for diagnostics ------------------------------
    ("  readAsmFile(argv[1], IndirectSet, &Main, IndirectCall, &Ret, argv[7]);\n",
     "  readAsmFile(argv[1], IndirectSet, &Main, IndirectCall, &Ret, argv[7]);\n"
     "  g_main_addr = (unsigned int)Main;   " + TAG + "\n"
     "  g_ret_addr = (unsigned int)Ret;\n", 1),
    # bail out if policy F was inconsistent
    ("  readTypeAmror(argv[3], IndirectCall);\n",
     "  readTypeAmror(argv[3], IndirectCall);\n"
     "  if (g_fatal)   " + TAG + "\n    return -1;\n", 1),

    # ---- main() becomes a callable function -------------------------------
    ("int main(int argc, char *argv[]) {\n",
     "static int recfa_check_main(int argc, char *argv[]) {   " + TAG + "\n", 1),
    ('    printf("Usage: ./check [disassem_file_path] [dyninst_graph_path] "\n'
     '           "[policy_F_path] [policy_M_path] [folded_runtime_event_path] "\n'
     '           "[num_executions] [compiler_type(gcc/llvm)].\\n");\n'
     "    return 0;\n",
     '    printf("Usage: ./check [disassem_file_path] [dyninst_graph_path] "\n'
     '           "[policy_F_path] [policy_M_path] [folded_runtime_event_path] "\n'
     '           "[num_executions] [compiler_type(gcc/llvm)].\\n");\n'
     "    return -1;   " + TAG + "\n",
     1),
    # main() must return a status; the entry point itself is appended at the end
    # of the file, because upstream declares st/count1/Maintotal *after* main.
    ('  cout << "Num of addresses attested: " << total << endl;\n}\n',
     '  cout << "Num of addresses attested: " << total << endl;\n'
     "  return 0;   " + TAG + "\n}\n",
     1),
]


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src_path = sys.argv[1]
    with open(src_path, "r", encoding="utf-8", errors="surrogateescape") as f:
        src = f.read()

    raw = open(src_path, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != UPSTREAM_SHA256:
        print("WARNING: upstream sha256 mismatch")
        print("  expected %s" % UPSTREAM_SHA256)
        print("  got      %s" % got)
        print("  the exact-match edits below may fail; review before trusting.")

    out = src
    for i, (old, new, count) in enumerate(EDITS):
        n = out.count(old)
        if n != count:
            raise SystemExit(
                "edit %d matched %d times, expected %d\n--- pattern ---\n%s"
                % (i, n, count, old)
            )
        out = out.replace(old, new)

    # Appended last: recfa_verify() touches globals (st, count1, Maintotal) that
    # upstream declares after main(), so it has to sit at the end of the file.
    if not out.endswith("\n"):
        out += "\n"
    out += ENTRY

    here = os.path.dirname(os.path.abspath(__file__))
    dst = os.path.join(here, "check.cpp")
    header = (
        "/* Vendored from upstream ReCFA (ACSAC'21) src/verifier/check.cpp\n"
        " *   https://github.com/suncongxd/ReCFA\n"
        " *   upstream sha256: %s\n"
        " *\n"
        " * DO NOT EDIT BY HAND. Regenerate with:\n"
        " *   python3 patch-upstream.py /path/to/ReCFA/src/verifier/check.cpp\n"
        " *\n"
        " * Every deviation from upstream carries a RECFA-PORT marker comment.\n"
        " */\n" % (UPSTREAM_SHA256,)
    )
    with open(dst, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(header + out)

    changed = out.count(TAG)
    print("wrote %s" % dst)
    print("applied %d edits, %d RECFA-PORT markers" % (len(EDITS), changed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
