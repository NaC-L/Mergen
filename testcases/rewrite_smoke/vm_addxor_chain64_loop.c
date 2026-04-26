/* PC-state VM running an add-xor chain on a single state over n iters:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r + x) ^ (x << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_addxor_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_subxor_chain64_loop (sister: sub instead of add)
 *   - vm_xormuladd_chain64_loop (xor + mul + add three-op)
 *
 * Tests `add i64` inside a counter-bound loop body chained with shl-3
 * and xor.  Pair with vm_subxor_chain64_loop completing the additive
 * direction of the same shape.
 */
#include <stdio.h>
#include <stdint.h>

enum AxVmPc {
    AX_INIT_ALL = 0,
    AX_CHECK    = 1,
    AX_BODY     = 2,
    AX_INC      = 3,
    AX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_addxor_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = AX_INIT_ALL;

    while (1) {
        if (pc == AX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = AX_CHECK;
        } else if (pc == AX_CHECK) {
            pc = (i < n) ? AX_BODY : AX_HALT;
        } else if (pc == AX_BODY) {
            r = (r + x) ^ (x << 3);
            pc = AX_INC;
        } else if (pc == AX_INC) {
            i = i + 1ull;
            pc = AX_CHECK;
        } else if (pc == AX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_addxor_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_addxor_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
