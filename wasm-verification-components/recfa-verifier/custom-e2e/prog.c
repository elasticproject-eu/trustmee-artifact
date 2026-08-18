/* Attestation target for the ReCFA end-to-end example.
 *
 * Small enough to reason about completely, while exercising every event class
 * the ReCFA attester records and the verifier checks:
 *
 *   - direct calls inside a loop        -> loop folding
 *   - three indirect call sites          -> policy F (from patched typearmor)
 *   - returns                            -> shadow stack
 *
 * The three indirect call sites deliberately pass a *different* number of
 * arguments (1, 2, 3). TypeArmor's rule is that a site may reach any
 * address-taken function whose consumed-argument count does not exceed what the
 * site prepares, so the sites end up with different permitted-target sets. Its
 * estimate of "prepared" is deliberately conservative — it counts argument
 * registers live at the call, so `apply1`'s site comes out at 3 rather than 1 —
 * but the ordering survives: the 4-argument `apply3` is permitted at the other
 * sites and *not* at `apply1`'s.
 *
 * That gap is what `tools/make-tamper.py` needs. It builds a hijack by
 * retargeting one site to a function that is real, and permitted at some *other*
 * site, but not at this one — a realistic call-site mismatch rather than random
 * corruption. Given a single call site, or sites that all permit the same
 * targets, it finds no candidate and exits with "no indirect call site occurs in
 * this trace".
 *
 * Build constraints, both load-bearing (see attester/gen-artifacts.sh):
 *   -no-pie  every address stays 6 hex digits at 0x4xxxxx, which upstream's
 *            regexes hardcode
 *   -g       the Dyninst mutator injects its fopen() call via
 *            appImage->findType("FILE"), which needs DWARF
 */
#include <stdio.h>

typedef int (*unop)(int);
typedef int (*binop)(int, int);
typedef int (*ternop)(int, int, int);

int neg(int x) { return -x; }

int square(int x) { return x * x; }

int add(int a, int b) { return a + b; }

int mul(int a, int b) { return a * b; }

int fma3(int a, int b, int c) { return a * b + c; }

/* One indirect call site each, preparing 1, 2 and 3 arguments. */
int apply1(unop f, int x) { return f(x); }

int apply2(binop f, int a, int b) { return f(a, b); }

int apply3(ternop f, int a, int b, int c) { return f(a, b, c); }

/* Dispatch tables, so the set of address-taken functions is non-degenerate:
 * every one of the five leaf functions is a candidate target somewhere. */
static const unop UNOPS[] = {neg, square};
static const binop BINOPS[] = {add, mul};
static const ternop TERNOPS[] = {fma3};

int main(void) {
  int acc = 1;

  for (int i = 1; i <= 3; i++) {
    acc = add(acc, i); /* direct call, three iterations -> folded */
  }

  acc = apply1(UNOPS[1], acc);         /* indirect, 1 arg:  square */
  acc = apply2(BINOPS[1], acc, 3);     /* indirect, 2 args: mul    */
  acc = apply3(TERNOPS[0], acc, 2, 5); /* indirect, 3 args: fma3   */

  FILE *f = fopen("prog.out", "w");
  if (f) {
    fprintf(f, "acc=%d\n", acc);
    fclose(f);
  }
  return 0;
}
