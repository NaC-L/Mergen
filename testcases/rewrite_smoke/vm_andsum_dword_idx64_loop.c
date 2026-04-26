/* PC-state VM that ADDs (u32 dword AND counter) into the accumulator
 * over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFFFFFFFF) & (i + 1));   // dword AND counter, ADD-folded
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_andsum_dword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_andsum_word_idx64_loop  (16-bit lane stride)
 *   - vm_andsum_byte_idx64_loop  (8-bit lane stride)
 *   - vm_orsum_dword_idx64_loop  (OR-folded counterpart at u32 stride)
 *
 * Tests AND-with-counter at u32 stride summed into i64.  Counter is
 * 1 or 2.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum AsdVmPc {
    ASD2_INIT_ALL = 0,
    ASD2_CHECK    = 1,
    ASD2_BODY     = 2,
    ASD2_INC      = 3,
    ASD2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_andsum_dword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ASD2_INIT_ALL;

    while (1) {
        if (pc == ASD2_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ASD2_CHECK;
        } else if (pc == ASD2_CHECK) {
            pc = (i < n) ? ASD2_BODY : ASD2_HALT;
        } else if (pc == ASD2_BODY) {
            r = r + ((s & 0xFFFFFFFFull) & (i + 1ull));
            s = s >> 32;
            pc = ASD2_INC;
        } else if (pc == ASD2_INC) {
            i = i + 1ull;
            pc = ASD2_CHECK;
        } else if (pc == ASD2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_andsum_dword_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_andsum_dword_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
