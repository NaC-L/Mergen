/* PC-state VM that builds r as a shift register fed from the top
 * with u32 dword lanes:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r >> 32) | ((s & 0xFFFFFFFF) << 32);   // shift in dword at top
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_shiftin_top_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_shiftin_top_word64_loop  (16-bit stride, lshr 16 / shl 48)
 *   - vm_shiftin_top64_loop       (8-bit stride, lshr 8 / shl 56)
 *
 * Tests `lshr i64 r, 32 | shl i64 dword, 32` shift-register update at
 * u32 stride.  After n=2 iterations the original input is reconstructed
 * (palindrome invariant).
 */
#include <stdio.h>
#include <stdint.h>

enum SitdVmPc {
    SITD_INIT_ALL = 0,
    SITD_CHECK    = 1,
    SITD_BODY     = 2,
    SITD_INC      = 3,
    SITD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_shiftin_top_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SITD_INIT_ALL;

    while (1) {
        if (pc == SITD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SITD_CHECK;
        } else if (pc == SITD_CHECK) {
            pc = (i < n) ? SITD_BODY : SITD_HALT;
        } else if (pc == SITD_BODY) {
            r = (r >> 32) | ((s & 0xFFFFFFFFull) << 32);
            s = s >> 32;
            pc = SITD_INC;
        } else if (pc == SITD_INC) {
            i = i + 1ull;
            pc = SITD_CHECK;
        } else if (pc == SITD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_shiftin_top_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_shiftin_top_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
