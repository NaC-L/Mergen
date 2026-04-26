/* PC-state VM running an FNV-1a-style hash chain over n = (x & 3) + 1
 * u16 words (canonical FNV is byte-oriented; this is the wider-lane
 * variant useful for stress-testing the lifter's xor-multiply chain
 * recognition at u16 stride):
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0xCBF29CE484222325;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFFFF)) * 0x100000001B3;
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv1a_word64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a64_loop  (byte-stride canonical FNV-1a)
 *   - vm_word_xormul64_loop (per-lane self-multiply, no constant accumulator basis)
 *
 * Tests xor-with-state then mul-by-prime at u16 stride starting from
 * the FNV offset basis.
 */
#include <stdio.h>
#include <stdint.h>

enum FwVmPc {
    FW_INIT_ALL = 0,
    FW_CHECK    = 1,
    FW_HASH     = 2,
    FW_SHIFT    = 3,
    FW_INC      = 4,
    FW_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv1a_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = FW_INIT_ALL;

    while (1) {
        if (pc == FW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = FW_CHECK;
        } else if (pc == FW_CHECK) {
            pc = (i < n) ? FW_HASH : FW_HALT;
        } else if (pc == FW_HASH) {
            r = (r ^ (s & 0xFFFFull)) * 0x100000001B3ull;
            pc = FW_SHIFT;
        } else if (pc == FW_SHIFT) {
            s = s >> 16;
            pc = FW_INC;
        } else if (pc == FW_INC) {
            i = i + 1ull;
            pc = FW_CHECK;
        } else if (pc == FW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv1a_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fnv1a_word64_loop_target(0xCAFEBABEull));
    return 0;
}
