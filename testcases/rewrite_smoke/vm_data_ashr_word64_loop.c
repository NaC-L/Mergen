/* PC-state VM with DATA-DEPENDENT arithmetic right-shift amount at u16
 * word stride:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w   = s & 0xFFFF;
 *     int      amt = (int)(w & 15);
 *     r = (uint64_t)((int64_t)r >> amt) + w;
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_data_ashr_word64_loop_target.
 *
 * Distinct from:
 *   - vm_data_ashr64_loop  (byte-stride, 3-bit shift amount mask)
 *   - vm_dynashr_accum_word64_loop (counter-derived shift, not data-derived)
 *
 * Tests `ashr i64 r, %word_amount` (signed right-shift by word-derived
 * 4-bit amount) with ADD fold at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum DawVmPc {
    DAW2_INIT_ALL = 0,
    DAW2_CHECK    = 1,
    DAW2_BODY     = 2,
    DAW2_INC      = 3,
    DAW2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_data_ashr_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DAW2_INIT_ALL;

    while (1) {
        if (pc == DAW2_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DAW2_CHECK;
        } else if (pc == DAW2_CHECK) {
            pc = (i < n) ? DAW2_BODY : DAW2_HALT;
        } else if (pc == DAW2_BODY) {
            uint64_t w   = s & 0xFFFFull;
            int      amt = (int)(w & 15ull);
            r = (uint64_t)((int64_t)r >> amt) + w;
            s = s >> 16;
            pc = DAW2_INC;
        } else if (pc == DAW2_INC) {
            i = i + 1ull;
            pc = DAW2_CHECK;
        } else if (pc == DAW2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_data_ashr_word64(0x8000000000000000)=%llu\n",
           (unsigned long long)vm_data_ashr_word64_loop_target(0x8000000000000000ull));
    return 0;
}
