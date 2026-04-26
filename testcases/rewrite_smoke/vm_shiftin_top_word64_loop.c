/* PC-state VM that builds r as a shift register fed from the top
 * with u16 word lanes:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> 16) | ((s & 0xFFFF) << 48);   // shift in word at top
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_shiftin_top_word64_loop_target.
 *
 * Distinct from:
 *   - vm_shiftin_top64_loop      (byte stride, lshr 8 / shl 56)
 *   - vm_word_orfold64_loop      (no shift register, just OR)
 *   - vm_byterev_window64_loop   (shl-or pack from low end)
 *
 * Tests `lshr i64 r, 16 | shl i64 word, 48` shift-register update
 * pattern at u16 stride.  After n=4 iterations with all-FFFF input, r
 * is preserved (palindrome invariant).
 */
#include <stdio.h>
#include <stdint.h>

enum SitwVmPc {
    SITW_INIT_ALL = 0,
    SITW_CHECK    = 1,
    SITW_BODY     = 2,
    SITW_INC      = 3,
    SITW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_shiftin_top_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SITW_INIT_ALL;

    while (1) {
        if (pc == SITW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SITW_CHECK;
        } else if (pc == SITW_CHECK) {
            pc = (i < n) ? SITW_BODY : SITW_HALT;
        } else if (pc == SITW_BODY) {
            r = (r >> 16) | ((s & 0xFFFFull) << 48);
            s = s >> 16;
            pc = SITW_INC;
        } else if (pc == SITW_INC) {
            i = i + 1ull;
            pc = SITW_CHECK;
        } else if (pc == SITW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_shiftin_top_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_shiftin_top_word64_loop_target(0xCAFEBABEull));
    return 0;
}
