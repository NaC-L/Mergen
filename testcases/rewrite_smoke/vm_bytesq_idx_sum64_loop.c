/* PC-state VM that sums byte * (i+1) * (i+1) over n = (x & 7) + 1 iters:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t c = i + 1;
 *     r = r + (s & 0xFF) * c * c;
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytesq_idx_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop (byte * counter, ADD) - linear counter
 *   - vm_xormul_byte_idx64_loop  (byte * counter, XOR) - linear counter
 *   - vm_bytesq_sum64_loop       (byte * byte - self-multiply, no counter)
 *
 * Tests SQUARED counter expression `(i+1)*(i+1)` as multiplier - two
 * sequential muls in the body (counter*counter then byte*counter^2)
 * inside a counter-bound loop.  All-0xFF: 0xFF * (1+4+9+16+25+36+49+64)
 * = 0xFF * 204 = 52020.
 */
#include <stdio.h>
#include <stdint.h>

enum BqVmPc {
    BQ_INIT_ALL = 0,
    BQ_CHECK    = 1,
    BQ_BODY     = 2,
    BQ_INC      = 3,
    BQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytesq_idx_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BQ_INIT_ALL;

    while (1) {
        if (pc == BQ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BQ_CHECK;
        } else if (pc == BQ_CHECK) {
            pc = (i < n) ? BQ_BODY : BQ_HALT;
        } else if (pc == BQ_BODY) {
            uint64_t c = i + 1ull;
            r = r + (s & 0xFFull) * c * c;
            s = s >> 8;
            pc = BQ_INC;
        } else if (pc == BQ_INC) {
            i = i + 1ull;
            pc = BQ_CHECK;
        } else if (pc == BQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytesq_idx_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_bytesq_idx_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
