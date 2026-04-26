/* PC-state VM that LSHRs r by (i+1) then XORs the u32 dword:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> (i + 1)) ^ (s & 0xFFFFFFFF);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dynlshr_accum_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_dynlshr_accum_word64_loop (16-bit lane stride)
 *   - vm_dynlshr_accum_byte64_loop (8-bit lane stride)
 *   - vm_dynashr_accum_dword64_loop (ashr counterpart at u32 stride)
 *   - vm_dynshl_accum_dword64_loop  (shl counterpart at u32 stride)
 *
 * Logical right-shift the accumulator by counter, then XOR with next
 * u32 lane.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DldVmPc {
    DLD_INIT_ALL = 0,
    DLD_CHECK    = 1,
    DLD_BODY     = 2,
    DLD_INC      = 3,
    DLD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynlshr_accum_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DLD_INIT_ALL;

    while (1) {
        if (pc == DLD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DLD_CHECK;
        } else if (pc == DLD_CHECK) {
            pc = (i < n) ? DLD_BODY : DLD_HALT;
        } else if (pc == DLD_BODY) {
            r = (r >> (i + 1ull)) ^ (s & 0xFFFFFFFFull);
            s = s >> 32;
            pc = DLD_INC;
        } else if (pc == DLD_INC) {
            i = i + 1ull;
            pc = DLD_CHECK;
        } else if (pc == DLD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynlshr_accum_dword64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dynlshr_accum_dword64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
