/* PC-state VM that sums byte % 3 over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFF) % 3);   // urem by 3
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytemod3_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytediv5_sum64_loop  (per-byte udiv by 5)
 *   - vm_adler32_64_loop      (urem by 65521 prime)
 *
 * Tests `urem i64 byte, 3` per iteration on a byte stream with ADD
 * accumulator.  Small-modulus complement to /5 sample - exercises
 * urem-by-small-prime separately from the div-by-5 path.  All-0xFF
 * accumulates 8 * (255 % 3) = 8 * 0 = 0.
 */
#include <stdio.h>
#include <stdint.h>

enum BmVmPc {
    BM_INIT_ALL = 0,
    BM_CHECK    = 1,
    BM_BODY     = 2,
    BM_INC      = 3,
    BM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytemod3_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BM_INIT_ALL;

    while (1) {
        if (pc == BM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BM_CHECK;
        } else if (pc == BM_CHECK) {
            pc = (i < n) ? BM_BODY : BM_HALT;
        } else if (pc == BM_BODY) {
            r = r + ((s & 0xFFull) % 3ull);
            s = s >> 8;
            pc = BM_INC;
        } else if (pc == BM_INC) {
            i = i + 1ull;
            pc = BM_CHECK;
        } else if (pc == BM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytemod3_sum64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_bytemod3_sum64_loop_target(0xDEADBEEFull));
    return 0;
}
