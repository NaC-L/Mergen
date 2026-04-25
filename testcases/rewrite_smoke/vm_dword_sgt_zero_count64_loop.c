/* PC-state VM that counts signed u32 dwords > 0:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     cnt = cnt + ((sd > 0) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_sgt_zero_count64_loop_target.
 *
 * Tests `icmp sgt 0` at u32 stride.  Dword-stride counterpart of
 * existing byte/word sgt samples.
 */
#include <stdio.h>
#include <stdint.h>

enum DsgVmPc {
    DSG_INIT_ALL = 0,
    DSG_CHECK    = 1,
    DSG_BODY     = 2,
    DSG_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_sgt_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DSG_INIT_ALL;

    while (1) {
        if (pc == DSG_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DSG_CHECK;
        } else if (pc == DSG_CHECK) {
            pc = (n > 0ull) ? DSG_BODY : DSG_HALT;
        } else if (pc == DSG_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            cnt = cnt + ((sd > (int32_t)0) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DSG_CHECK;
        } else if (pc == DSG_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_sgt_zero_count64(0x800000017FFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_sgt_zero_count64_loop_target(0x800000017FFFFFFFull));
    return 0;
}
