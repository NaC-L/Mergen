/* PC-state VM that SHLs r by (i+1) then adds the u32 dword:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r << (i + 1)) + (s & 0xFFFFFFFF);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_accum_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_accum_word64_loop (16-bit lane stride)
 *   - vm_dynshl_accum_byte64_loop (8-bit lane stride)
 *   - vm_dynashr_accum_dword64_loop (ashr counterpart at u32 stride)
 *   - vm_dynlshr_accum_dword64_loop (lshr counterpart at u32 stride)
 *
 * Left-shift the accumulator by counter (1..2), then add next u32 lane.
 * Wraps at u64.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DshdVmPc {
    DSHD_INIT_ALL = 0,
    DSHD_CHECK    = 1,
    DSHD_BODY     = 2,
    DSHD_INC      = 3,
    DSHD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_accum_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DSHD_INIT_ALL;

    while (1) {
        if (pc == DSHD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DSHD_CHECK;
        } else if (pc == DSHD_CHECK) {
            pc = (i < n) ? DSHD_BODY : DSHD_HALT;
        } else if (pc == DSHD_BODY) {
            r = (r << (i + 1ull)) + (s & 0xFFFFFFFFull);
            s = s >> 32;
            pc = DSHD_INC;
        } else if (pc == DSHD_INC) {
            i = i + 1ull;
            pc = DSHD_CHECK;
        } else if (pc == DSHD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_accum_dword64(0x0000000100000003)=%llu\n",
           (unsigned long long)vm_dynshl_accum_dword64_loop_target(0x0000000100000003ull));
    return 0;
}
