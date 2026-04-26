/* PC-state VM that sums u16 word % 3 over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFFFF) % 3);   // urem by 3
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_wordmod3_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytemod3_sum64_loop  (8-bit stride)
 *   - vm_worddiv5_sum64_loop  (udiv by 5 counterpart)
 *
 * Tests `urem i64 word, 3` per iteration on a u16 word stream with ADD
 * accumulator at u16 stride.  Each lane contributes 0..2; max sum over
 * 4 lanes is 8.
 */
#include <stdio.h>
#include <stdint.h>

enum WmodVmPc {
    WMOD_INIT_ALL = 0,
    WMOD_CHECK    = 1,
    WMOD_BODY     = 2,
    WMOD_INC      = 3,
    WMOD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_wordmod3_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WMOD_INIT_ALL;

    while (1) {
        if (pc == WMOD_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WMOD_CHECK;
        } else if (pc == WMOD_CHECK) {
            pc = (i < n) ? WMOD_BODY : WMOD_HALT;
        } else if (pc == WMOD_BODY) {
            r = r + ((s & 0xFFFFull) % 3ull);
            s = s >> 16;
            pc = WMOD_INC;
        } else if (pc == WMOD_INC) {
            i = i + 1ull;
            pc = WMOD_CHECK;
        } else if (pc == WMOD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordmod3_sum64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_wordmod3_sum64_loop_target(0xDEADBEEFull));
    return 0;
}
