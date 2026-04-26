/* PC-state VM with DATA-DEPENDENT right-shift amount inside the loop
 * at u16 word stride:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = ~0;     // start with all-1s
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = (r >> (w & 15)) ^ w;   // lshr amount comes from word data low 4 bits
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_data_lshr_word64_loop_target.
 *
 * Distinct from:
 *   - vm_data_lshr64_loop  (byte-stride, 3-bit shift amount mask)
 *   - vm_dynlshr_accum_word64_loop (counter-derived shift, not data-derived)
 *
 * Tests `lshr i64 r, %word_amount` (right-shift by word-derived 4-bit
 * amount).  Combined with XOR fold of the raw word.
 */
#include <stdio.h>
#include <stdint.h>

enum DlwVmPc {
    DLW2_INIT_ALL = 0,
    DLW2_CHECK    = 1,
    DLW2_BODY     = 2,
    DLW2_INC      = 3,
    DLW2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_data_lshr_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DLW2_INIT_ALL;

    while (1) {
        if (pc == DLW2_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0xFFFFFFFFFFFFFFFFull;
            i = 0ull;
            pc = DLW2_CHECK;
        } else if (pc == DLW2_CHECK) {
            pc = (i < n) ? DLW2_BODY : DLW2_HALT;
        } else if (pc == DLW2_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = (r >> (w & 15ull)) ^ w;
            s = s >> 16;
            pc = DLW2_INC;
        } else if (pc == DLW2_INC) {
            i = i + 1ull;
            pc = DLW2_CHECK;
        } else if (pc == DLW2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_data_lshr_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_data_lshr_word64_loop_target(0xCAFEBABEull));
    return 0;
}
