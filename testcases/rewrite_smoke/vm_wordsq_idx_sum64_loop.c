/* PC-state VM that ADDs (u16 word * c^2) into the accumulator over
 * n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t c = i + 1;
 *     r = r + (s & 0xFFFF) * c * c;
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_wordsq_idx_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_idx_sum64_loop  (8-bit lane stride)
 *   - vm_uintadd_word_idx64_loop (lane * counter, no counter-square)
 *   - vm_wordsq_sum64_loop      (lane*lane, no counter scaling)
 *
 * Tests u16 lane * c * c (chained mul) ADD-folded at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum WqiVmPc {
    WQI_INIT_ALL = 0,
    WQI_CHECK    = 1,
    WQI_BODY     = 2,
    WQI_INC      = 3,
    WQI_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_wordsq_idx_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WQI_INIT_ALL;

    while (1) {
        if (pc == WQI_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WQI_CHECK;
        } else if (pc == WQI_CHECK) {
            pc = (i < n) ? WQI_BODY : WQI_HALT;
        } else if (pc == WQI_BODY) {
            uint64_t c = i + 1ull;
            r = r + (s & 0xFFFFull) * c * c;
            s = s >> 16;
            pc = WQI_INC;
        } else if (pc == WQI_INC) {
            i = i + 1ull;
            pc = WQI_CHECK;
        } else if (pc == WQI_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordsq_idx_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_wordsq_idx_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
