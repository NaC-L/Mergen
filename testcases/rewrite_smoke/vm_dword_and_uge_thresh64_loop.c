/* PC-state VM that AND-accumulates u32 dwords >= 0x80000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; acc = 0xFFFFFFFF;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     acc = acc & ((d >= 0x80000000) ? d : 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_dword_and_uge_thresh64_loop_target.
 *
 * Predicate-gated AND accumulator at u32 stride (identity 0xFFFFFFFF).
 * Completes the AND reducer at all 3 widths.
 */
#include <stdio.h>
#include <stdint.h>

enum DandVmPc {
    DAND_INIT_ALL = 0,
    DAND_CHECK    = 1,
    DAND_BODY     = 2,
    DAND_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_and_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = DAND_INIT_ALL;

    while (1) {
        if (pc == DAND_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            acc = 0xFFFFFFFFull;
            pc = DAND_CHECK;
        } else if (pc == DAND_CHECK) {
            pc = (n > 0ull) ? DAND_BODY : DAND_HALT;
        } else if (pc == DAND_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            acc = acc & ((d >= 0x80000000ull) ? d : 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DAND_CHECK;
        } else if (pc == DAND_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_and_uge_thresh64(0x800000017FFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_and_uge_thresh64_loop_target(0x800000017FFFFFFFull));
    return 0;
}
