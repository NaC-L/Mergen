/* PC-state VM running a sub-xor chain on a single state over n iters:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r - x) ^ (x << 3);
 *   }
 *   return r;
 *
 * Lift target: vm_subxor_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_xorbytes64_loop        (XOR-only over byte stream)
 *   - vm_horner64_loop          (mul + add polynomial)
 *
 * Tests `sub i64` inside a counter-bound loop body chained with shl-3
 * and xor.  Sub is underused vs add in the existing sample set; this
 * sample exercises i64 subtract on a state that gets re-derived from
 * itself minus the input each iteration.  Note: r starts seeded with
 * x so that the first iter's (r - x) lands at zero before the xor.
 */
#include <stdio.h>
#include <stdint.h>

enum SxVmPc {
    SX_INIT_ALL = 0,
    SX_CHECK    = 1,
    SX_BODY     = 2,
    SX_INC      = 3,
    SX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_subxor_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SX_INIT_ALL;

    while (1) {
        if (pc == SX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = SX_CHECK;
        } else if (pc == SX_CHECK) {
            pc = (i < n) ? SX_BODY : SX_HALT;
        } else if (pc == SX_BODY) {
            r = (r - x) ^ (x << 3);
            pc = SX_INC;
        } else if (pc == SX_INC) {
            i = i + 1ull;
            pc = SX_CHECK;
        } else if (pc == SX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_subxor_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_subxor_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
