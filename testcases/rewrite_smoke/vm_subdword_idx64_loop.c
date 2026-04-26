/* PC-state VM that SUBs unsigned-u32 * counter from the accumulator
 * over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r - (s & 0xFFFFFFFF) * (i + 1);   // u32 zext * counter, SUB-folded
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_subdword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_subword_idx64_loop       (16-bit lane stride)
 *   - vm_subbyte_idx64_loop       (8-bit lane stride)
 *   - vm_uintadd_dword_idx64_loop (ADD-folded counterpart at u32 stride)
 *
 * Tests unsigned dword (zext-i32) * counter SUB-folded into i64
 * accumulator at u32 stride.  Result wraps below zero into u64.
 * Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum SbdVmPc {
    SBD_INIT_ALL = 0,
    SBD_CHECK    = 1,
    SBD_BODY     = 2,
    SBD_INC      = 3,
    SBD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_subdword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SBD_INIT_ALL;

    while (1) {
        if (pc == SBD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SBD_CHECK;
        } else if (pc == SBD_CHECK) {
            pc = (i < n) ? SBD_BODY : SBD_HALT;
        } else if (pc == SBD_BODY) {
            r = r - (s & 0xFFFFFFFFull) * (i + 1ull);
            s = s >> 32;
            pc = SBD_INC;
        } else if (pc == SBD_INC) {
            i = i + 1ull;
            pc = SBD_CHECK;
        } else if (pc == SBD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_subdword_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_subdword_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
