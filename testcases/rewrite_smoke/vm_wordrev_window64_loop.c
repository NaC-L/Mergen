/* PC-state VM that packs the lower n = (x & 3) + 1 u16 words of x
 * into the accumulator r in REVERSED word order:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 16) | (s & 0xFFFF);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_wordrev_window64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop (byte stride, shl 8 / lshr 8)
 *   - vm_word_orfold64_loop    (no shift, simple OR fold)
 *
 * Tests shl-by-16 + or + lshr-by-16 chain inside a counter-bound loop
 * body at u16 stride.  Trip count 1..4.  n=4 with all 0xFFFF input is
 * a palindrome.
 */
#include <stdio.h>
#include <stdint.h>

enum WvVmPc {
    WV_INIT_ALL = 0,
    WV_CHECK    = 1,
    WV_PACK     = 2,
    WV_SHIFT    = 3,
    WV_INC      = 4,
    WV_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_wordrev_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WV_INIT_ALL;

    while (1) {
        if (pc == WV_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WV_CHECK;
        } else if (pc == WV_CHECK) {
            pc = (i < n) ? WV_PACK : WV_HALT;
        } else if (pc == WV_PACK) {
            r = (r << 16) | (s & 0xFFFFull);
            pc = WV_SHIFT;
        } else if (pc == WV_SHIFT) {
            s = s >> 16;
            pc = WV_INC;
        } else if (pc == WV_INC) {
            i = i + 1ull;
            pc = WV_CHECK;
        } else if (pc == WV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordrev_window64(0x0001000200030004)=%llu\n",
           (unsigned long long)vm_wordrev_window64_loop_target(0x0001000200030004ull));
    return 0;
}
