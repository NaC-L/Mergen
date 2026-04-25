/* PC-state VM running a two-state recurrence with arithmetic negation:
 *
 *   n = (x & 7) + 1;
 *   r = 0; s = x;
 *   for (i = 0; i < n; i++) {
 *     r = -r + s;        // negate accumulator, add stepped state
 *     s = s + 1;
 *   }
 *   return r;
 *
 * Lift target: vm_negstep64_loop_target.
 *
 * Distinct from:
 *   - vm_subxor_chain64_loop (`(r-x)^(x<<3)` - sub of state minus input)
 *   - vm_xormuladd_chain64_loop (xor + mul + add)
 *   - vm_geosum64_loop / vm_squareadd64_loop (single-state arith)
 *
 * Tests the `sub i64 0, r` (negate) pattern inside a counter-bound
 * loop body chained with add and a stepped state.  The negation flips
 * sign of the accumulator each iter; with even trip count the sign
 * cancels out for many inputs.
 */
#include <stdio.h>
#include <stdint.h>

enum NgVmPc {
    NG_INIT_ALL = 0,
    NG_CHECK    = 1,
    NG_BODY     = 2,
    NG_INC      = 3,
    NG_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_negstep64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t s  = 0;
    uint64_t i  = 0;
    int      pc = NG_INIT_ALL;

    while (1) {
        if (pc == NG_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            s = x;
            i = 0ull;
            pc = NG_CHECK;
        } else if (pc == NG_CHECK) {
            pc = (i < n) ? NG_BODY : NG_HALT;
        } else if (pc == NG_BODY) {
            uint64_t nr = (uint64_t)(-(int64_t)r);
            r = nr + s;
            s = s + 1ull;
            pc = NG_INC;
        } else if (pc == NG_INC) {
            i = i + 1ull;
            pc = NG_CHECK;
        } else if (pc == NG_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_negstep64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_negstep64_loop_target(0xCAFEBABEull));
    return 0;
}
