/* PC-state VM that ASHRs r by (i+1) then adds the byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (uint64_t)((int64_t)r >> (i + 1)) + (s & 0xFF);
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynashr_accum_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_accum_byte64_loop  (shl accumulator by counter)
 *   - vm_dynlshr_accum_byte64_loop (lshr accumulator by counter)
 *   - vm_data_ashr64_loop          (ashr accumulator by byte data)
 *
 * Completes the counter-driven accumulator-shift trio (shl/lshr/ashr).
 * Sign-extending right-shift propagates the high bit of running r
 * through iterations - high-bit-set seeds (e.g. 2^63) sign-extend
 * to all-1s before the byte add.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_INC      = 3,
    DA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynashr_accum_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            r = (uint64_t)((int64_t)r >> (int)(i + 1ull)) + (s & 0xFFull);
            s = s >> 8;
            pc = DA_INC;
        } else if (pc == DA_INC) {
            i = i + 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynashr_accum_byte64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_dynashr_accum_byte64_loop_target(0x8000000000000000ull));
    return 0;
}
