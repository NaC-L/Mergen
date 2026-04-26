/* PC-state VM that ASHRs r by (i+1) then adds the u32 dword:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = (uint64_t)((int64_t)r >> (i + 1)) + (s & 0xFFFFFFFF);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dynashr_accum_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_dynashr_accum_word64_loop (16-bit lane stride)
 *   - vm_dynashr_accum_byte64_loop (8-bit lane stride)
 *   - vm_dynshl_accum_dword64_loop  (shl counterpart at u32 stride)
 *   - vm_dynlshr_accum_dword64_loop (lshr counterpart at u32 stride)
 *
 * Sign-extending right-shift propagates the high bit of r through
 * iterations.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DadVmPc {
    DAD_INIT_ALL = 0,
    DAD_CHECK    = 1,
    DAD_BODY     = 2,
    DAD_INC      = 3,
    DAD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynashr_accum_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DAD_INIT_ALL;

    while (1) {
        if (pc == DAD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DAD_CHECK;
        } else if (pc == DAD_CHECK) {
            pc = (i < n) ? DAD_BODY : DAD_HALT;
        } else if (pc == DAD_BODY) {
            r = (uint64_t)((int64_t)r >> (int)(i + 1ull)) + (s & 0xFFFFFFFFull);
            s = s >> 32;
            pc = DAD_INC;
        } else if (pc == DAD_INC) {
            i = i + 1ull;
            pc = DAD_CHECK;
        } else if (pc == DAD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynashr_accum_dword64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_dynashr_accum_dword64_loop_target(0x8000000000000000ull));
    return 0;
}
