/* PC-state VM that SUBs unsigned-u16 * counter from the accumulator
 * over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r - (s & 0xFFFF) * (i + 1);   // u16 zext * counter, SUB-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_subword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_subbyte_idx64_loop      (8-bit lane stride)
 *   - vm_uintadd_word_idx64_loop (ADD-folded counterpart at u16 stride)
 *
 * Tests unsigned word (zext-i16) * counter SUB-folded into i64
 * accumulator at u16 stride.  Result wraps below zero into u64.
 */
#include <stdio.h>
#include <stdint.h>

enum SbwVmPc {
    SBW_INIT_ALL = 0,
    SBW_CHECK    = 1,
    SBW_BODY     = 2,
    SBW_INC      = 3,
    SBW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_subword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SBW_INIT_ALL;

    while (1) {
        if (pc == SBW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SBW_CHECK;
        } else if (pc == SBW_CHECK) {
            pc = (i < n) ? SBW_BODY : SBW_HALT;
        } else if (pc == SBW_BODY) {
            r = r - (s & 0xFFFFull) * (i + 1ull);
            s = s >> 16;
            pc = SBW_INC;
        } else if (pc == SBW_INC) {
            i = i + 1ull;
            pc = SBW_CHECK;
        } else if (pc == SBW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_subword_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_subword_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
