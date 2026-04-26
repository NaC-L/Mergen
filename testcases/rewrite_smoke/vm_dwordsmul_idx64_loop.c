/* PC-state VM that ADDs (sext-i32 dword) * counter into the accumulator
 * over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     r = r + (int64_t)sd * (int64_t)(i + 1);
 *     s >>= 32;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_dwordsmul_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_wordsmul_idx64_loop      (16-bit lane stride)
 *   - vm_bytesmul_idx64_loop      (8-bit lane stride)
 *   - vm_uintadd_dword_idx64_loop (zext-i32 ADD counterpart at u32 stride)
 *
 * Tests sext-i32 dword * counter ADD-folded into i64 accumulator at u32
 * stride.  Lanes with high-bit set (>=0x80000000) contribute negatively.
 */
#include <stdio.h>
#include <stdint.h>

enum DsmVmPc {
    DSM_INIT_ALL = 0,
    DSM_CHECK    = 1,
    DSM_BODY     = 2,
    DSM_INC      = 3,
    DSM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dwordsmul_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = DSM_INIT_ALL;

    while (1) {
        if (pc == DSM_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = DSM_CHECK;
        } else if (pc == DSM_CHECK) {
            pc = (i < n) ? DSM_BODY : DSM_HALT;
        } else if (pc == DSM_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            r = r + (int64_t)sd * (int64_t)(i + 1ull);
            s = s >> 32;
            pc = DSM_INC;
        } else if (pc == DSM_INC) {
            i = i + 1ull;
            pc = DSM_CHECK;
        } else if (pc == DSM_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordsmul_idx64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_dwordsmul_idx64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
