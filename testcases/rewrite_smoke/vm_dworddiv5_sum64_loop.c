/* PC-state VM that sums u32 dword / 5 over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFFFFFFFF) / 5);   // udiv by 5
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dworddiv5_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_worddiv5_sum64_loop  (16-bit stride)
 *   - vm_bytediv5_sum64_loop  (8-bit stride)
 *   - vm_dwordmod3_sum64_loop (urem by 3 counterpart)
 *
 * Tests `udiv i64 dword, 5` per iteration at u32 stride.  Trip count
 * <= 2.  All-0xFFFFFFFF (n=2) accumulates 2 * 858993459 = 1717986918.
 */
#include <stdio.h>
#include <stdint.h>

enum DdivVmPc {
    DDIV_INIT_ALL = 0,
    DDIV_CHECK    = 1,
    DDIV_BODY     = 2,
    DDIV_INC      = 3,
    DDIV_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dworddiv5_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DDIV_INIT_ALL;

    while (1) {
        if (pc == DDIV_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DDIV_CHECK;
        } else if (pc == DDIV_CHECK) {
            pc = (i < n) ? DDIV_BODY : DDIV_HALT;
        } else if (pc == DDIV_BODY) {
            r = r + ((s & 0xFFFFFFFFull) / 5ull);
            s = s >> 32;
            pc = DDIV_INC;
        } else if (pc == DDIV_INC) {
            i = i + 1ull;
            pc = DDIV_CHECK;
        } else if (pc == DDIV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dworddiv5_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dworddiv5_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
