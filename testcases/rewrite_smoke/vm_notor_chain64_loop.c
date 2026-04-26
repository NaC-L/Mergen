/* PC-state VM running a NOT-OR chain with dynamic-shift xor:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (~r) | x;
 *     r = r ^ (i << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_notor_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_notand_chain64_loop (NOT-AND counterpart)
 *
 * Tests bitwise NOT followed by OR with input, then xor with `i<<3`.
 * Pairs with vm_notand_chain64_loop completing the NOT/AND vs NOT/OR
 * pair.  `(~r) | x` is logically equivalent to `~(r & ~x)` but the
 * lifter sees the NOT-OR form directly.
 */
#include <stdio.h>
#include <stdint.h>

enum NoVmPc {
    NO_INIT_ALL = 0,
    NO_CHECK    = 1,
    NO_BODY     = 2,
    NO_INC      = 3,
    NO_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_notor_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = NO_INIT_ALL;

    while (1) {
        if (pc == NO_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = NO_CHECK;
        } else if (pc == NO_CHECK) {
            pc = (i < n) ? NO_BODY : NO_HALT;
        } else if (pc == NO_BODY) {
            r = (~r) | x;
            r = r ^ (i << 3);
            pc = NO_INC;
        } else if (pc == NO_INC) {
            i = i + 1ull;
            pc = NO_CHECK;
        } else if (pc == NO_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_notor_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_notor_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
