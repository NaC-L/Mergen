/* PC-state VM that packs the lower n = (x & 7) + 1 bytes of x into the
 * accumulator r in REVERSED byte order:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 8) | (s & 0xFF);
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byterev_window64_loop_target.
 *
 * Distinct from vm_bswap64_loop which is a fixed 8-byte byteswap (and
 * gets folded to llvm.bswap.i64).  Here the trip count is symbolic
 * (1..8), so the result is the reverse of the lowest n bytes only --
 * which the lifter cannot collapse to a single intrinsic.  Tests
 * shl-by-8 + or + lshr-by-8 chain inside a counter-bound loop body.
 *
 * Special cases worth noting:
 *   - n=1: r ends up equal to byte0 (no rotation possible)
 *   - n=8 with all 0xFF: result is the same all-0xFF input (palindrome)
 */
#include <stdio.h>
#include <stdint.h>

enum BvVmPc {
    BV_INIT_ALL = 0,
    BV_CHECK    = 1,
    BV_PACK     = 2,
    BV_SHIFT    = 3,
    BV_INC      = 4,
    BV_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_byterev_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BV_INIT_ALL;

    while (1) {
        if (pc == BV_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BV_CHECK;
        } else if (pc == BV_CHECK) {
            pc = (i < n) ? BV_PACK : BV_HALT;
        } else if (pc == BV_PACK) {
            r = (r << 8) | (s & 0xFFull);
            pc = BV_SHIFT;
        } else if (pc == BV_SHIFT) {
            s = s >> 8;
            pc = BV_INC;
        } else if (pc == BV_INC) {
            i = i + 1ull;
            pc = BV_CHECK;
        } else if (pc == BV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byterev_window64(0x0102030405060708)=%llu\n",
           (unsigned long long)vm_byterev_window64_loop_target(0x0102030405060708ull));
    return 0;
}
