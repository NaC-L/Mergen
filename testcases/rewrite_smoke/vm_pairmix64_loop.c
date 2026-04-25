/* PC-state VM that runs a two-state cross-feeding mix step over n iters:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = ~x;
 *   for (i = 0; i < n; i++) {
 *     t = a + b;
 *     a = b * 0x9E3779B97F4A7C15ull;
 *     b = t ^ (t >> 33);
 *   }
 *   return a ^ b;
 *
 * Lift target: vm_pairmix64_loop_target.
 *
 * Distinct from:
 *   - vm_xorrot64_loop (xor-then-LCG, one accumulator reads input each iter)
 *   - vm_murmurstep64_loop (single-state Murmur chain reading input each iter)
 *   - vm_geosum64_loop / vm_squareadd64_loop (single-state recurrences)
 *   - vm_tea_round_loop (REMOVED - lifter mis-lifted compound v0/v1
 *     cross-update; THIS sample uses an explicit temp `t` so reads of
 *     a and b happen BEFORE either is overwritten, sidestepping that bug)
 *
 * Two i64 slots (a, b) plus a per-iter temp (t).  Each iteration reads
 * both states into t, then writes a and b from disjoint expressions.
 * Tests cross-feeding lifting with a temp barrier between read and
 * write, exercising i64 mul, xor, lshr-33, and add.
 */
#include <stdio.h>
#include <stdint.h>

enum PmVmPc {
    PM_INIT_ALL = 0,
    PM_CHECK    = 1,
    PM_BODY     = 2,
    PM_INC      = 3,
    PM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_pairmix64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = PM_INIT_ALL;

    while (1) {
        if (pc == PM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = ~x;
            i = 0ull;
            pc = PM_CHECK;
        } else if (pc == PM_CHECK) {
            pc = (i < n) ? PM_BODY : PM_HALT;
        } else if (pc == PM_BODY) {
            uint64_t t = a + b;
            a = b * 0x9E3779B97F4A7C15ull;
            b = t ^ (t >> 33);
            pc = PM_INC;
        } else if (pc == PM_INC) {
            i = i + 1ull;
            pc = PM_CHECK;
        } else if (pc == PM_HALT) {
            return a ^ b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pairmix64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pairmix64_loop_target(0xCAFEBABEull));
    return 0;
}
