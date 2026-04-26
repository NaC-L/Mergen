/* PC-state VM running an LCG-style recurrence with the ANSI C rand()
 * multiplier and SUBTRACTIVE increment over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r * 1103515245 - 12345;     // SUB instead of ADD
 *   }
 *   return r;
 *
 * Lift target: vm_lcg_ansi_chain_sub64_loop_target.
 *
 * Distinct from:
 *   - vm_lcg_ansi_chain64_loop (sister: ADD instead of SUB)
 *
 * Single i64 LCG with subtractive increment - tests u64 modular wrap
 * inside the recurrence in the opposite direction from the ANSI rand()
 * variant.
 */
#include <stdio.h>
#include <stdint.h>

enum LcsVmPc {
    LCS_INIT_ALL = 0,
    LCS_CHECK    = 1,
    LCS_BODY     = 2,
    LCS_INC      = 3,
    LCS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_lcg_ansi_chain_sub64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = LCS_INIT_ALL;

    while (1) {
        if (pc == LCS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = LCS_CHECK;
        } else if (pc == LCS_CHECK) {
            pc = (i < n) ? LCS_BODY : LCS_HALT;
        } else if (pc == LCS_BODY) {
            r = r * 1103515245ull - 12345ull;
            pc = LCS_INC;
        } else if (pc == LCS_INC) {
            i = i + 1ull;
            pc = LCS_CHECK;
        } else if (pc == LCS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_lcg_ansi_chain_sub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_lcg_ansi_chain_sub64_loop_target(0xCAFEBABEull));
    return 0;
}
