/* PC-state VM that counts signed u32 dwords <= 0:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     cnt = cnt + ((sd <= 0) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_sle_zero_count64_loop_target.
 *
 * Tests `icmp sle 0` at u32 stride.  Completes the signed-predicate
 * cmp-counter matrix at u8/u16/u32 strides for slt/sle/sgt/sge.
 */
#include <stdio.h>
#include <stdint.h>

enum DsleVmPc {
    DSLE_INIT_ALL = 0,
    DSLE_CHECK    = 1,
    DSLE_BODY     = 2,
    DSLE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_sle_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DSLE_INIT_ALL;

    while (1) {
        if (pc == DSLE_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DSLE_CHECK;
        } else if (pc == DSLE_CHECK) {
            pc = (n > 0ull) ? DSLE_BODY : DSLE_HALT;
        } else if (pc == DSLE_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            cnt = cnt + ((sd <= (int32_t)0) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DSLE_CHECK;
        } else if (pc == DSLE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_sle_zero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_sle_zero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
