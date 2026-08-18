/* C entry point exposed by the vendored ReCFA verifier (check.cpp) to the
 * Rust Wasm component shell. See vendor/patch-upstream.py for provenance.
 */
#ifndef RECFA_ENTRY_H
#define RECFA_ENTRY_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verdicts. 1 is the only accepting value; everything else is a rejection.
 * 2..4 are CFI verdicts derived from the evidence; 5..7 mean the inputs were
 * inconsistent or malformed, which is also a rejection (fail closed). */
#define RECFA_VERDICT_UNKNOWN 0      /* verifier returned without a verdict     */
#define RECFA_VERDICT_SECURE 1       /* "No events left unprocessed"            */
#define RECFA_VERDICT_SHADOW 2       /* "fail,N events unprocessed"             */
#define RECFA_VERDICT_ICALL 3        /* "Indirect Call": target not in policy F */
#define RECFA_VERDICT_IJMP 4         /* "Indirect Jump": target not in the CFG  */
#define RECFA_VERDICT_DYNINST 5      /* "dyninst fail": policy M vs CFG mismatch*/
#define RECFA_VERDICT_POLICY_F 6     /* "Policy F read error"                   */
/* NB: a compressed event naming an unknown call site is deliberately NOT a
 * verdict of its own. Well-formed traces do it (the trailing run marker becomes
 * the end sentinel), so such events flow into normal verification and are
 * rejected there by the shadow stack or the policy sets if they are bogus. */

/* 64-bit members first and fixed-width types throughout, so the layout is
 * unambiguous and matches Rust's #[repr(C)] with no implicit padding. */
typedef struct {
  int64_t events_attested;      /* upstream `total`                            */
  int64_t events_unprocessed;   /* queue depth at a shadow-stack failure       */
  int64_t events_reconstructed; /* upstream `success` (call sites re-inserted)  */
  int32_t verdict;              /* RECFA_VERDICT_*                             */
  uint32_t policy_m_entries;    /* |M|                                         */
  uint32_t policy_f_entries;    /* |F| (== proMap.size())                      */
  uint32_t violation_site;      /* transfer instruction that failed            */
  uint32_t violation_target;    /* the disallowed target                       */
  uint32_t main_addr;           /* resolved <main>                             */
  uint32_t main_ret_addr;       /* first retq in <main>                        */
} recfa_result;

/* Register an input buffer under the name later passed to recfa_verify(). The
 * bytes are copied. */
void recfa_vfs_put(const char *name, const unsigned char *data,
                   unsigned long len);
void recfa_vfs_clear(void);

/* Run the verifier over the registered buffers.
 * Returns 0 if the verifier ran to completion (inspect out->verdict), non-zero
 * if the inputs were rejected before verification began. */
int recfa_verify(const char *asm_name, const char *dot_name, const char *f_name,
                 const char *m_name, const char *trace_name,
                 int num_executions, const char *compiler_type,
                 recfa_result *out);

#ifdef __cplusplus
}
#endif

#endif /* RECFA_ENTRY_H */
