/* PC-state VM that builds r as a shift register fed from the top:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> 8) | ((s & 0xFF) << 56);   // shift in byte at top
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_shiftin_top64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop (shl-or pack from low end)
 *   - vm_nibrev_window64_loop  (4-bit shift-or pack)
 *   - vm_byte_loop / vm_xorbytes64_loop (no shift register pattern)
 *
 * Tests `lshr i64 r, 8 | shl i64 byte, 56` shift-register update
 * pattern.  After n=8 iterations with all-FF input, r is preserved
 * (palindrome invariant); for n < 8 the upper bytes of r are filled
 * with x's lower bytes shifted into MSB position one at a time.
 */
#include <stdio.h>
#include <stdint.h>

enum StVmPc {
    ST_INIT_ALL = 0,
    ST_CHECK    = 1,
    ST_BODY     = 2,
    ST_INC      = 3,
    ST_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_shiftin_top64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ST_INIT_ALL;

    while (1) {
        if (pc == ST_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ST_CHECK;
        } else if (pc == ST_CHECK) {
            pc = (i < n) ? ST_BODY : ST_HALT;
        } else if (pc == ST_BODY) {
            r = (r >> 8) | ((s & 0xFFull) << 56);
            s = s >> 8;
            pc = ST_INC;
        } else if (pc == ST_INC) {
            i = i + 1ull;
            pc = ST_CHECK;
        } else if (pc == ST_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_shiftin_top64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_shiftin_top64_loop_target(0xDEADBEEFull));
    return 0;
}
