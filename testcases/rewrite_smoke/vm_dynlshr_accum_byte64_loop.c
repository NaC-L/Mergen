/* PC-state VM that shifts r right by (i+1) bits then XORs the byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = ~0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> (i + 1)) ^ (s & 0xFF);   // lshr ACCUMULATOR by counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynlshr_accum_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_accum_byte64_loop (shl accumulator by counter, ADD)
 *   - vm_bitfetch_window64_loop   (lshr INPUT by counter, OR fold)
 *   - vm_data_lshr64_loop         (lshr accumulator by byte data)
 *
 * Tests `lshr i64 %r, %(i+1)` (lshr accumulator by phi-tracked
 * counter expression) chained with byte XOR fold.  Initial r=~0
 * means the first iter shifts a saturated state down by 1 before
 * XOR with byte0.
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
uint64_t vm_dynlshr_accum_byte64_loop_target(uint64_t x) {
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
            r = (r >> (i + 1ull)) ^ (s & 0xFFull);
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
    printf("vm_dynlshr_accum_byte64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dynlshr_accum_byte64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
