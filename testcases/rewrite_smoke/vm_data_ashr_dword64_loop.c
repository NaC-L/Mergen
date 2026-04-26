/* PC-state VM with DATA-DEPENDENT arithmetic right-shift amount at u32
 * dword stride:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d   = s & 0xFFFFFFFF;
 *     int      amt = (int)(d & 31);
 *     r = (uint64_t)((int64_t)r >> amt) + d;
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_data_ashr_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_data_ashr_word64_loop (16-bit stride, 4-bit shift amount mask)
 *   - vm_data_ashr64_loop      (byte stride, 3-bit shift amount mask)
 *
 * Tests `ashr i64 r, %dword_amount` (signed right-shift by dword-derived
 * 5-bit amount) with ADD fold at u32 stride.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DadVmPc {
    DAD2_INIT_ALL = 0,
    DAD2_CHECK    = 1,
    DAD2_BODY     = 2,
    DAD2_INC      = 3,
    DAD2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_data_ashr_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DAD2_INIT_ALL;

    while (1) {
        if (pc == DAD2_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DAD2_CHECK;
        } else if (pc == DAD2_CHECK) {
            pc = (i < n) ? DAD2_BODY : DAD2_HALT;
        } else if (pc == DAD2_BODY) {
            uint64_t d   = s & 0xFFFFFFFFull;
            int      amt = (int)(d & 31ull);
            r = (uint64_t)((int64_t)r >> amt) + d;
            s = s >> 32;
            pc = DAD2_INC;
        } else if (pc == DAD2_INC) {
            i = i + 1ull;
            pc = DAD2_CHECK;
        } else if (pc == DAD2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_data_ashr_dword64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_data_ashr_dword64_loop_target(0x8000000000000000ull));
    return 0;
}
