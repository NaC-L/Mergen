/* PC-state VM that ADDs (u16 word AND counter) into the accumulator
 * over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFFFF) & (i + 1));   // word AND counter, ADD-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_andsum_word_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_andsum_byte_idx64_loop  (8-bit lane stride)
 *   - vm_orsum_word_idx64_loop   (OR-folded counterpart at u16 stride)
 *
 * Tests AND-with-counter at u16 stride summed into i64.  Counter is
 * a small constant (i+1 in 1..4 for word stride), so the AND mask
 * stays in a tight bit window.
 */
#include <stdio.h>
#include <stdint.h>

enum AswVmPc {
    ASW2_INIT_ALL = 0,
    ASW2_CHECK    = 1,
    ASW2_BODY     = 2,
    ASW2_INC      = 3,
    ASW2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_andsum_word_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ASW2_INIT_ALL;

    while (1) {
        if (pc == ASW2_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ASW2_CHECK;
        } else if (pc == ASW2_CHECK) {
            pc = (i < n) ? ASW2_BODY : ASW2_HALT;
        } else if (pc == ASW2_BODY) {
            r = r + ((s & 0xFFFFull) & (i + 1ull));
            s = s >> 16;
            pc = ASW2_INC;
        } else if (pc == ASW2_INC) {
            i = i + 1ull;
            pc = ASW2_CHECK;
        } else if (pc == ASW2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_andsum_word_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_andsum_word_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
