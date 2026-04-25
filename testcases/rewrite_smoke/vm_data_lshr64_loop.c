/* PC-state VM with DATA-DEPENDENT right-shift amount inside the loop:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = ~0;     // start with all-1s
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = (r >> (b & 7)) ^ b;   // lshr amount comes from byte data
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_data_lshr64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl_data64_loop  (data-dependent SHL counterpart)
 *   - vm_bitfetch_window64_loop (lshr by loop counter)
 *   - vm_dyn_ashr64_loop      (ashr by loop counter)
 *
 * Tests `lshr i64 r, %byte_amount` (right-shift by byte-derived
 * amount).  Combined with XOR fold of the raw byte.  Initial r=~0
 * means the first iter shifts a saturated state down by a
 * data-driven amount before XOR.
 */
#include <stdio.h>
#include <stdint.h>

enum DlVmPc {
    DL_INIT_ALL = 0,
    DL_CHECK    = 1,
    DL_BODY     = 2,
    DL_INC      = 3,
    DL_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_data_lshr64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DL_INIT_ALL;

    while (1) {
        if (pc == DL_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xFFFFFFFFFFFFFFFFull;
            i = 0ull;
            pc = DL_CHECK;
        } else if (pc == DL_CHECK) {
            pc = (i < n) ? DL_BODY : DL_HALT;
        } else if (pc == DL_BODY) {
            uint64_t b = s & 0xFFull;
            r = (r >> (b & 7ull)) ^ b;
            s = s >> 8;
            pc = DL_INC;
        } else if (pc == DL_INC) {
            i = i + 1ull;
            pc = DL_CHECK;
        } else if (pc == DL_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_data_lshr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_data_lshr64_loop_target(0xDEADBEEFull));
    return 0;
}
