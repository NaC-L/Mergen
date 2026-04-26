/* PC-state VM that ASHRs r by (i+1) then adds the u16 word:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (uint64_t)((int64_t)r >> (i + 1)) + (s & 0xFFFF);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_dynashr_accum_word64_loop_target.
 *
 * Distinct from:
 *   - vm_dynashr_accum_byte64_loop (8-bit lane stride, same accumulator-shift idiom)
 *   - vm_dynshl_accum_word64_loop  (shl counterpart at u16 stride)
 *   - vm_dynlshr_accum_word64_loop (lshr counterpart at u16 stride)
 *
 * Sign-extending right-shift propagates the high bit of r through
 * iterations.  Counter-driven shift amount, u16 lane add.
 */
#include <stdio.h>
#include <stdint.h>

enum DawVmPc {
    DAW_INIT_ALL = 0,
    DAW_CHECK    = 1,
    DAW_BODY     = 2,
    DAW_INC      = 3,
    DAW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynashr_accum_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DAW_INIT_ALL;

    while (1) {
        if (pc == DAW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DAW_CHECK;
        } else if (pc == DAW_CHECK) {
            pc = (i < n) ? DAW_BODY : DAW_HALT;
        } else if (pc == DAW_BODY) {
            r = (uint64_t)((int64_t)r >> (int)(i + 1ull)) + (s & 0xFFFFull);
            s = s >> 16;
            pc = DAW_INC;
        } else if (pc == DAW_INC) {
            i = i + 1ull;
            pc = DAW_CHECK;
        } else if (pc == DAW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynashr_accum_word64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_dynashr_accum_word64_loop_target(0x8000000000000000ull));
    return 0;
}
