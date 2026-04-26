/* PC-state VM that sums squared u16 words over n = (x & 3) + 1 iters:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = r + w * w;          // u16 squared, ADD-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_wordsq_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_sum64_loop  (8-bit stride)
 *   - vm_word_xormul64_loop (per-word self-multiply but XOR-folded)
 *
 * Tests u16 self-multiply (w * w) accumulator across a word stream
 * with ADD fold.  All-0xFFFF input accumulates 4 * 0xFFFE0001.
 */
#include <stdio.h>
#include <stdint.h>

enum WqVmPc {
    WQ_INIT_ALL = 0,
    WQ_CHECK    = 1,
    WQ_BODY     = 2,
    WQ_INC      = 3,
    WQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_wordsq_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WQ_INIT_ALL;

    while (1) {
        if (pc == WQ_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WQ_CHECK;
        } else if (pc == WQ_CHECK) {
            pc = (i < n) ? WQ_BODY : WQ_HALT;
        } else if (pc == WQ_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = r + w * w;
            s = s >> 16;
            pc = WQ_INC;
        } else if (pc == WQ_INC) {
            i = i + 1ull;
            pc = WQ_CHECK;
        } else if (pc == WQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordsq_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_wordsq_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
