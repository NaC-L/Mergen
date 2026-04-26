/* PC-state VM running an xxhash-style per-byte mix chain with the
 * xor/mul order SWAPPED (multiply first, then xor):
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xCAFEBABEDEADBEEF;
 *   for (i = 0; i < n; i++) {
 *     r = (r * 0xC2B2AE3D27D4EB4Full) ^ (s & 0xFF);   // mul-then-xor
 *     s >>= 8;
 *   }
 *   r = r ^ (r >> 33);
 *   return r;
 *
 * Lift target: vm_xxhmix_mulxor64_loop_target.
 *
 * Distinct from:
 *   - vm_xxhmix64_loop (sister: r = (r ^ b) * P3 instead of (r * P3) ^ b)
 *
 * Tests mul-then-xor with the 64-bit xxhash PRIME64_3 multiplier per
 * byte, with the same final xor-fold by lshr 33 outside the loop.
 */
#include <stdio.h>
#include <stdint.h>

enum XxmVmPc {
    XXM_INIT_ALL = 0,
    XXM_CHECK    = 1,
    XXM_MIX      = 2,
    XXM_SHIFT    = 3,
    XXM_INC      = 4,
    XXM_FOLD     = 5,
    XXM_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_xxhmix_mulxor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XXM_INIT_ALL;

    while (1) {
        if (pc == XXM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xCAFEBABEDEADBEEFull;
            i = 0ull;
            pc = XXM_CHECK;
        } else if (pc == XXM_CHECK) {
            pc = (i < n) ? XXM_MIX : XXM_FOLD;
        } else if (pc == XXM_MIX) {
            r = (r * 0xC2B2AE3D27D4EB4Full) ^ (s & 0xFFull);
            pc = XXM_SHIFT;
        } else if (pc == XXM_SHIFT) {
            s = s >> 8;
            pc = XXM_INC;
        } else if (pc == XXM_INC) {
            i = i + 1ull;
            pc = XXM_CHECK;
        } else if (pc == XXM_FOLD) {
            r = r ^ (r >> 33);
            pc = XXM_HALT;
        } else if (pc == XXM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xxhmix_mulxor64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xxhmix_mulxor64_loop_target(0xCAFEBABEull));
    return 0;
}
