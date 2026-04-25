/* PC-state VM running the classic ANSI C rand() LCG over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r * 1103515245 + 12345;   // ANSI rand() constants
 *   }
 *   return r;
 *
 * Lift target: vm_lcg_ansi_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xorrot64_loop          (LCG with golden-ratio multiplier + xor accum)
 *   - vm_pcg64_loop             (PCG random)
 *   - vm_xorshift64_loop        (Marsaglia three-shift xorshift)
 *   - vm_squareadd64_loop       (single-state quadratic recurrence)
 *
 * Tests linear-congruential recurrence with the canonical ANSI C
 * rand() multiplier (1103515245) and increment (12345) chained for
 * n iterations.  Single i64 state, no input read inside the body
 * (only seeded by x at INIT_ALL).
 */
#include <stdio.h>
#include <stdint.h>

enum LcVmPc {
    LC_INIT_ALL = 0,
    LC_CHECK    = 1,
    LC_BODY     = 2,
    LC_INC      = 3,
    LC_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_lcg_ansi_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = LC_INIT_ALL;

    while (1) {
        if (pc == LC_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = LC_CHECK;
        } else if (pc == LC_CHECK) {
            pc = (i < n) ? LC_BODY : LC_HALT;
        } else if (pc == LC_BODY) {
            r = r * 1103515245ull + 12345ull;
            pc = LC_INC;
        } else if (pc == LC_INC) {
            i = i + 1ull;
            pc = LC_CHECK;
        } else if (pc == LC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_lcg_ansi_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_lcg_ansi_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
