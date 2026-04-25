/* PC-state VM that counts signed u32 dwords >= 0:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     cnt = cnt + ((sd >= 0) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_sge_zero_count64_loop_target.
 *
 * Tests `icmp sge 0` at u32 stride.  Dword-stride counterpart of
 * existing byte/word sge samples.
 */
#include <stdio.h>
#include <stdint.h>

enum DsgeVmPc {
    DSGE_INIT_ALL = 0,
    DSGE_CHECK    = 1,
    DSGE_BODY     = 2,
    DSGE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_sge_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DSGE_INIT_ALL;

    while (1) {
        if (pc == DSGE_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DSGE_CHECK;
        } else if (pc == DSGE_CHECK) {
            pc = (n > 0ull) ? DSGE_BODY : DSGE_HALT;
        } else if (pc == DSGE_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            cnt = cnt + ((sd >= (int32_t)0) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DSGE_CHECK;
        } else if (pc == DSGE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_sge_zero_count64(0x7FFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_sge_zero_count64_loop_target(0x7FFFFFFFull));
    return 0;
}
