/* PC-state VM running a NOT-AND chain with dynamic-shift xor:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (~r) & x;
 *     r = r ^ (i << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_notand_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_subxor_chain64_loop    (sub + shl + xor)
 *   - vm_negstep64_loop         (negate + add)
 *
 * Tests bitwise NOT (`xor i64 r, -1`) followed by AND with input,
 * then xor with `i << 3` where i is the loop-index phi.  Combines
 * the bitwise NOT/AND idiom (also known as `andn`) with a dynamic
 * left-shift xor.
 */
#include <stdio.h>
#include <stdint.h>

enum NaVmPc {
    NA_INIT_ALL = 0,
    NA_CHECK    = 1,
    NA_BODY     = 2,
    NA_INC      = 3,
    NA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_notand_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = NA_INIT_ALL;

    while (1) {
        if (pc == NA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = NA_CHECK;
        } else if (pc == NA_CHECK) {
            pc = (i < n) ? NA_BODY : NA_HALT;
        } else if (pc == NA_BODY) {
            r = (~r) & x;
            r = r ^ (i << 3);
            pc = NA_INC;
        } else if (pc == NA_INC) {
            i = i + 1ull;
            pc = NA_CHECK;
        } else if (pc == NA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_notand_chain64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_notand_chain64_loop_target(0xDEADBEEFull));
    return 0;
}
