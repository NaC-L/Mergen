/* PC-state VM that sums u32 dword % 3 over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFFFFFFFF) % 3);   // urem by 3
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordmod3_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_wordmod3_sum64_loop  (16-bit stride)
 *   - vm_bytemod3_sum64_loop  (8-bit stride)
 *   - vm_dworddiv5_sum64_loop (udiv by 5 counterpart)
 *
 * Tests `urem i64 dword, 3` per iteration on a u32 dword stream with
 * ADD accumulator at u32 stride.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DmodVmPc {
    DMOD_INIT_ALL = 0,
    DMOD_CHECK    = 1,
    DMOD_BODY     = 2,
    DMOD_INC      = 3,
    DMOD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dwordmod3_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DMOD_INIT_ALL;

    while (1) {
        if (pc == DMOD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DMOD_CHECK;
        } else if (pc == DMOD_CHECK) {
            pc = (i < n) ? DMOD_BODY : DMOD_HALT;
        } else if (pc == DMOD_BODY) {
            r = r + ((s & 0xFFFFFFFFull) % 3ull);
            s = s >> 32;
            pc = DMOD_INC;
        } else if (pc == DMOD_INC) {
            i = i + 1ull;
            pc = DMOD_CHECK;
        } else if (pc == DMOD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordmod3_sum64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_dwordmod3_sum64_loop_target(0xDEADBEEFull));
    return 0;
}
