/* PC-state VM that sums u16 word / 5 over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFFFF) / 5);   // udiv by 5
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_worddiv5_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytediv5_sum64_loop  (8-bit stride)
 *   - vm_wordmod3_sum64_loop  (urem by 3 counterpart)
 *
 * Tests `udiv i64 word, 5` per iteration at u16 stride.  Each lane
 * contributes up to 0xFFFF/5 = 13107.  All-0xFFFF (n=4) accumulates
 * 4 * 13107 = 52428.
 */
#include <stdio.h>
#include <stdint.h>

enum WdivVmPc {
    WDIV_INIT_ALL = 0,
    WDIV_CHECK    = 1,
    WDIV_BODY     = 2,
    WDIV_INC      = 3,
    WDIV_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_worddiv5_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WDIV_INIT_ALL;

    while (1) {
        if (pc == WDIV_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WDIV_CHECK;
        } else if (pc == WDIV_CHECK) {
            pc = (i < n) ? WDIV_BODY : WDIV_HALT;
        } else if (pc == WDIV_BODY) {
            r = r + ((s & 0xFFFFull) / 5ull);
            s = s >> 16;
            pc = WDIV_INC;
        } else if (pc == WDIV_INC) {
            i = i + 1ull;
            pc = WDIV_CHECK;
        } else if (pc == WDIV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_worddiv5_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_worddiv5_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
