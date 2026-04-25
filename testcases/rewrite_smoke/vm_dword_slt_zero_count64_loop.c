/* PC-state VM that counts signed u32 dwords < 0:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     cnt = cnt + ((sd < 0) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_slt_zero_count64_loop_target.
 *
 * Tests `icmp slt 0` at u32 stride.  Dword-stride counterpart of
 * existing byte/word slt samples.
 */
#include <stdio.h>
#include <stdint.h>

enum DslVmPc {
    DSL_INIT_ALL = 0,
    DSL_CHECK    = 1,
    DSL_BODY     = 2,
    DSL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_slt_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DSL_INIT_ALL;

    while (1) {
        if (pc == DSL_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DSL_CHECK;
        } else if (pc == DSL_CHECK) {
            pc = (n > 0ull) ? DSL_BODY : DSL_HALT;
        } else if (pc == DSL_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            cnt = cnt + ((sd < (int32_t)0) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DSL_CHECK;
        } else if (pc == DSL_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_slt_zero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_slt_zero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
