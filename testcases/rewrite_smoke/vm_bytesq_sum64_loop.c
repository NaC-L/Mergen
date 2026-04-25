/* PC-state VM that sums squared bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r + b * b;          // u8 squared
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytesq_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_popsq64_loop           (sum of squared POPCOUNTS of bytes)
 *   - vm_squareadd64_loop       (single-state r = r*r + i quadratic)
 *   - vm_uintadd_byte_idx64_loop (byte * counter)
 *
 * Tests u8 self-multiply (b * b) accumulator across a byte stream.
 * No counter scaling; every byte squared and summed.  All-0xFF input
 * accumulates 8 * 255*255 = 8 * 65025 = 520200.
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
uint64_t vm_bytesq_sum64_loop_target(uint64_t x) {
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
            uint64_t b = s & 0xFFull;
            r = r + b * b;
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
    printf("vm_bytesq_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_bytesq_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
