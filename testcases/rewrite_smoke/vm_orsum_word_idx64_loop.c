/* PC-state VM that ORs (u16 word OR counter) into the accumulator
 * over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r | ((s & 0xFFFF) | (i + 1));   // word OR counter, OR-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_orsum_word_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_orsum_byte_idx64_loop   (8-bit lane stride)
 *   - vm_andsum_word_idx64_loop  (AND-folded counterpart at u16 stride)
 *   - vm_word_orfold64_loop      (pure OR fold without counter contribution)
 *
 * Tests (lane | counter) chained through OR fold at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum OswVmPc {
    OSW_INIT_ALL = 0,
    OSW_CHECK    = 1,
    OSW_BODY     = 2,
    OSW_INC      = 3,
    OSW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orsum_word_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = OSW_INIT_ALL;

    while (1) {
        if (pc == OSW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = OSW_CHECK;
        } else if (pc == OSW_CHECK) {
            pc = (i < n) ? OSW_BODY : OSW_HALT;
        } else if (pc == OSW_BODY) {
            r = r | ((s & 0xFFFFull) | (i + 1ull));
            s = s >> 16;
            pc = OSW_INC;
        } else if (pc == OSW_INC) {
            i = i + 1ull;
            pc = OSW_CHECK;
        } else if (pc == OSW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orsum_word_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_orsum_word_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
