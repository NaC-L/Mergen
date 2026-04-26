/* PC-state VM running an xxhash-style per-u16-word mix chain over
 * n=(x&3)+1 words, with a final xor-fold:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0xCAFEBABEDEADBEEF;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFFFF)) * 0xC2B2AE3D27D4EB4F;   // xxhash PRIME64_3
 *     s >>= 16;
 *   }
 *   r = r ^ (r >> 33);
 *   return r;
 *
 * Lift target: vm_xxhmix_word64_loop_target.
 *
 * Distinct from:
 *   - vm_xxhmix64_loop (8-bit lane stride)
 *   - vm_murmur_word_chain64_loop (different magic, fold INSIDE loop)
 *   - vm_fnv1a_word64_loop (no fold, different prime)
 *
 * Tests xor-then-mul with a 64-bit xxhash multiplier per word, then a
 * final xor-fold by lshr 33 outside the loop at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum XxwVmPc {
    XXW_INIT_ALL = 0,
    XXW_CHECK    = 1,
    XXW_MIX      = 2,
    XXW_SHIFT    = 3,
    XXW_INC      = 4,
    XXW_FOLD     = 5,
    XXW_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_xxhmix_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XXW_INIT_ALL;

    while (1) {
        if (pc == XXW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0xCAFEBABEDEADBEEFull;
            i = 0ull;
            pc = XXW_CHECK;
        } else if (pc == XXW_CHECK) {
            pc = (i < n) ? XXW_MIX : XXW_FOLD;
        } else if (pc == XXW_MIX) {
            r = (r ^ (s & 0xFFFFull)) * 0xC2B2AE3D27D4EB4Full;
            pc = XXW_SHIFT;
        } else if (pc == XXW_SHIFT) {
            s = s >> 16;
            pc = XXW_INC;
        } else if (pc == XXW_INC) {
            i = i + 1ull;
            pc = XXW_CHECK;
        } else if (pc == XXW_FOLD) {
            r = r ^ (r >> 33);
            pc = XXW_HALT;
        } else if (pc == XXW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xxhmix_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xxhmix_word64_loop_target(0xCAFEBABEull));
    return 0;
}
