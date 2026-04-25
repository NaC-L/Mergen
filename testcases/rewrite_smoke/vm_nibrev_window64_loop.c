/* PC-state VM that reverses the lower n = (x & 7) + 1 NIBBLES of x:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 4) | (s & 0xF);
 *     s >>= 4;
 *   }
 *   return r;
 *
 * Lift target: vm_nibrev_window64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop (8-bit window, shl/lshr by 8)
 *   - vm_nibrev64_loop         (full fixed 16-nibble reverse, may fold)
 *
 * Tests shl-by-4 + or + lshr-by-4 chain inside a counter-bound loop.
 * Trip count maxes at 8, so even with n=8 only the lower 32 bits of
 * x are consumed -- the upper half of x is irrelevant to the result.
 * Single-trip cases (n=1) reduce to the low nibble of x.
 */
#include <stdio.h>
#include <stdint.h>

enum NwVmPc {
    NW_INIT_ALL = 0,
    NW_CHECK    = 1,
    NW_PACK     = 2,
    NW_SHIFT    = 3,
    NW_INC      = 4,
    NW_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_nibrev_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = NW_INIT_ALL;

    while (1) {
        if (pc == NW_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = NW_CHECK;
        } else if (pc == NW_CHECK) {
            pc = (i < n) ? NW_PACK : NW_HALT;
        } else if (pc == NW_PACK) {
            r = (r << 4) | (s & 0xFull);
            pc = NW_SHIFT;
        } else if (pc == NW_SHIFT) {
            s = s >> 4;
            pc = NW_INC;
        } else if (pc == NW_INC) {
            i = i + 1ull;
            pc = NW_CHECK;
        } else if (pc == NW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nibrev_window64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_nibrev_window64_loop_target(0xDEADBEEFull));
    return 0;
}
