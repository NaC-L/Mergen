/* PC-state VM that LSHRs r by (i+1) then XORs the u16 word:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> (i + 1)) ^ (s & 0xFFFF);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_dynlshr_accum_word64_loop_target.
 *
 * Distinct from:
 *   - vm_dynlshr_accum_byte64_loop (8-bit lane stride)
 *   - vm_dynashr_accum_word64_loop (ashr counterpart at u16 stride)
 *   - vm_dynshl_accum_word64_loop  (shl counterpart at u16 stride)
 *
 * Logical right-shift the accumulator by counter, then XOR with next
 * u16 lane.  Counter-driven shift amount.
 */
#include <stdio.h>
#include <stdint.h>

enum DlwVmPc {
    DLW_INIT_ALL = 0,
    DLW_CHECK    = 1,
    DLW_BODY     = 2,
    DLW_INC      = 3,
    DLW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynlshr_accum_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DLW_INIT_ALL;

    while (1) {
        if (pc == DLW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DLW_CHECK;
        } else if (pc == DLW_CHECK) {
            pc = (i < n) ? DLW_BODY : DLW_HALT;
        } else if (pc == DLW_BODY) {
            r = (r >> (i + 1ull)) ^ (s & 0xFFFFull);
            s = s >> 16;
            pc = DLW_INC;
        } else if (pc == DLW_INC) {
            i = i + 1ull;
            pc = DLW_CHECK;
        } else if (pc == DLW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynlshr_accum_word64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dynlshr_accum_word64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
