/* PC-state VM that ADDs (u32 dword * c^2) into the accumulator over
 * n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t c = i + 1;
 *     r = r + (s & 0xFFFFFFFF) * c * c;
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordsq_idx_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_wordsq_idx_sum64_loop  (16-bit lane stride)
 *   - vm_bytesq_idx_sum64_loop  (8-bit lane stride)
 *   - vm_uintadd_dword_idx64_loop (lane * counter, no counter-square)
 *
 * Tests u32 lane * c * c (chained mul) ADD-folded at u32 stride.
 * Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DqiVmPc {
    DQI_INIT_ALL = 0,
    DQI_CHECK    = 1,
    DQI_BODY     = 2,
    DQI_INC      = 3,
    DQI_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dwordsq_idx_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DQI_INIT_ALL;

    while (1) {
        if (pc == DQI_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DQI_CHECK;
        } else if (pc == DQI_CHECK) {
            pc = (i < n) ? DQI_BODY : DQI_HALT;
        } else if (pc == DQI_BODY) {
            uint64_t c = i + 1ull;
            r = r + (s & 0xFFFFFFFFull) * c * c;
            s = s >> 32;
            pc = DQI_INC;
        } else if (pc == DQI_INC) {
            i = i + 1ull;
            pc = DQI_CHECK;
        } else if (pc == DQI_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordsq_idx_sum64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_dwordsq_idx_sum64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
