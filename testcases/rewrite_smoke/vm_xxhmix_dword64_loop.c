/* PC-state VM running an xxhash-style per-u32-dword mix chain over
 * n=(x&1)+1 dwords, with a final xor-fold:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0xCAFEBABEDEADBEEF;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFFFFFFFF)) * 0xC2B2AE3D27D4EB4F;
 *     s >>= 32;
 *   }
 *   r = r ^ (r >> 33);
 *   return r;
 *
 * Lift target: vm_xxhmix_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_xxhmix_word64_loop (16-bit lane stride)
 *   - vm_xxhmix64_loop      (8-bit lane stride)
 *   - vm_murmur_dword_chain64_loop (different magic, fold INSIDE loop)
 *
 * Tests xor-then-mul with a 64-bit xxhash multiplier per dword, then a
 * final xor-fold by lshr 33 outside the loop at u32 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum XxdVmPc {
    XXD_INIT_ALL = 0,
    XXD_CHECK    = 1,
    XXD_MIX      = 2,
    XXD_SHIFT    = 3,
    XXD_INC      = 4,
    XXD_FOLD     = 5,
    XXD_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_xxhmix_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XXD_INIT_ALL;

    while (1) {
        if (pc == XXD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0xCAFEBABEDEADBEEFull;
            i = 0ull;
            pc = XXD_CHECK;
        } else if (pc == XXD_CHECK) {
            pc = (i < n) ? XXD_MIX : XXD_FOLD;
        } else if (pc == XXD_MIX) {
            r = (r ^ (s & 0xFFFFFFFFull)) * 0xC2B2AE3D27D4EB4Full;
            pc = XXD_SHIFT;
        } else if (pc == XXD_SHIFT) {
            s = s >> 32;
            pc = XXD_INC;
        } else if (pc == XXD_INC) {
            i = i + 1ull;
            pc = XXD_CHECK;
        } else if (pc == XXD_FOLD) {
            r = r ^ (r >> 33);
            pc = XXD_HALT;
        } else if (pc == XXD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xxhmix_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xxhmix_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
