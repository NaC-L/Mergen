/* PC-state VM that SHLs r by (i+1) then adds the u16 word:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r << (i + 1)) + (s & 0xFFFF);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_accum_word64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_accum_byte64_loop (8-bit lane stride)
 *   - vm_dynashr_accum_word64_loop (ashr counterpart at u16 stride)
 *   - vm_dynlshr_accum_word64_loop (lshr counterpart at u16 stride)
 *
 * Left-shift the accumulator by counter (1..4), then add next u16 lane.
 * Wraps at u64.
 */
#include <stdio.h>
#include <stdint.h>

enum DshwVmPc {
    DSHW_INIT_ALL = 0,
    DSHW_CHECK    = 1,
    DSHW_BODY     = 2,
    DSHW_INC      = 3,
    DSHW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_accum_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DSHW_INIT_ALL;

    while (1) {
        if (pc == DSHW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DSHW_CHECK;
        } else if (pc == DSHW_CHECK) {
            pc = (i < n) ? DSHW_BODY : DSHW_HALT;
        } else if (pc == DSHW_BODY) {
            r = (r << (i + 1ull)) + (s & 0xFFFFull);
            s = s >> 16;
            pc = DSHW_INC;
        } else if (pc == DSHW_INC) {
            i = i + 1ull;
            pc = DSHW_CHECK;
        } else if (pc == DSHW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_accum_word64(0x0001000200030004)=%llu\n",
           (unsigned long long)vm_dynshl_accum_word64_loop_target(0x0001000200030004ull));
    return 0;
}
