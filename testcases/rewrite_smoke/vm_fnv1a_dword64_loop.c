/* PC-state VM running an FNV-1a-style hash chain over n = (x & 1) + 1
 * u32 dwords (canonical FNV is byte-oriented; this is the wider-lane
 * variant useful for stress-testing the lifter's xor-multiply chain
 * recognition at u32 stride):
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0xCBF29CE484222325;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFFFFFFFF)) * 0x100000001B3;
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv1a_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a_word64_loop (16-bit lane stride)
 *   - vm_fnv1a64_loop      (byte-stride canonical FNV-1a)
 *   - vm_dword_xormul64_loop (per-lane self-multiply, no constant accumulator basis)
 *
 * Tests xor-with-state then mul-by-prime at u32 stride starting from
 * the FNV offset basis.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum FdVmPc {
    FD_INIT_ALL = 0,
    FD_CHECK    = 1,
    FD_HASH     = 2,
    FD_SHIFT    = 3,
    FD_INC      = 4,
    FD_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv1a_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = FD_INIT_ALL;

    while (1) {
        if (pc == FD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = FD_CHECK;
        } else if (pc == FD_CHECK) {
            pc = (i < n) ? FD_HASH : FD_HALT;
        } else if (pc == FD_HASH) {
            r = (r ^ (s & 0xFFFFFFFFull)) * 0x100000001B3ull;
            pc = FD_SHIFT;
        } else if (pc == FD_SHIFT) {
            s = s >> 32;
            pc = FD_INC;
        } else if (pc == FD_INC) {
            i = i + 1ull;
            pc = FD_CHECK;
        } else if (pc == FD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv1a_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_fnv1a_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
