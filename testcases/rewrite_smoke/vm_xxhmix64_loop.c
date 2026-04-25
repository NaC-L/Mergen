/* PC-state VM running an xxhash-style per-byte mix chain over n=(x&7)+1
 * bytes, with a final xor-fold:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xCAFEBABEDEADBEEF;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFF)) * 0xC2B2AE3D27D4EB4Full;   // xxhash PRIME64_3
 *     s >>= 8;
 *   }
 *   r = r ^ (r >> 33);
 *   return r;
 *
 * Lift target: vm_xxhmix64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a64_loop      (xor-then-multiply by 40-bit FNV prime)
 *   - vm_murmurstep64_loop (no byte windowing; xor with x each iter)
 *   - vm_djb264_loop       (additive *33)
 *   - vm_horner64_loop     (polynomial)
 *
 * Tests xor-then-mul with a 64-bit xxhash multiplier per byte, then a
 * final xor-fold by lshr 33 outside the loop.  Different magic
 * constant from FNV (0x100000001B3) and Murmur (0xC6A4A7935BD1E995).
 */
#include <stdio.h>
#include <stdint.h>

enum XxVmPc {
    XX_INIT_ALL = 0,
    XX_CHECK    = 1,
    XX_MIX      = 2,
    XX_SHIFT    = 3,
    XX_INC      = 4,
    XX_FOLD     = 5,
    XX_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_xxhmix64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XX_INIT_ALL;

    while (1) {
        if (pc == XX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xCAFEBABEDEADBEEFull;
            i = 0ull;
            pc = XX_CHECK;
        } else if (pc == XX_CHECK) {
            pc = (i < n) ? XX_MIX : XX_FOLD;
        } else if (pc == XX_MIX) {
            r = (r ^ (s & 0xFFull)) * 0xC2B2AE3D27D4EB4Full;
            pc = XX_SHIFT;
        } else if (pc == XX_SHIFT) {
            s = s >> 8;
            pc = XX_INC;
        } else if (pc == XX_INC) {
            i = i + 1ull;
            pc = XX_CHECK;
        } else if (pc == XX_FOLD) {
            r = r ^ (r >> 33);
            pc = XX_HALT;
        } else if (pc == XX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xxhmix64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xxhmix64_loop_target(0xCAFEBABEull));
    return 0;
}
