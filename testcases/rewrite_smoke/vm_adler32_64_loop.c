/* PC-state VM that runs an Adler-32-style two-accumulator modular hash
 * over n = (x & 7) + 1 bytes consumed from the input register:
 *
 *   n = (x & 7) + 1;
 *   s = x; a = 1; b = 0;
 *   for (i = 0; i < n; i++) {
 *     a = (a + (s & 0xFF)) % 65521;     // ADLER prime
 *     b = (b + a)         % 65521;
 *     s >>= 8;
 *   }
 *   return (b << 16) | a;
 *
 * Lift target: vm_adler32_64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a64_loop  (single state, multiplicative)
 *   - vm_djb264_loop   (single additive multiplier)
 *   - vm_byterange64_loop (two reductions but no modular arithmetic)
 *
 * Two PARALLEL additive accumulators where b feeds on the running a.
 * Each modular step exercises i64 urem by 65521 (a non-power-of-2
 * prime) which the lifter must lower via magic-number division.
 * The result packs both accumulators into one i64 via shl-or.
 */
#include <stdio.h>
#include <stdint.h>

enum AdVmPc {
    AD_INIT_ALL = 0,
    AD_CHECK    = 1,
    AD_STEP_A   = 2,
    AD_STEP_B   = 3,
    AD_SHIFT    = 4,
    AD_INC      = 5,
    AD_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_adler32_64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = AD_INIT_ALL;

    while (1) {
        if (pc == AD_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            a = 1ull;
            b = 0ull;
            i = 0ull;
            pc = AD_CHECK;
        } else if (pc == AD_CHECK) {
            pc = (i < n) ? AD_STEP_A : AD_HALT;
        } else if (pc == AD_STEP_A) {
            a = (a + (s & 0xFFull)) % 65521ull;
            pc = AD_STEP_B;
        } else if (pc == AD_STEP_B) {
            b = (b + a) % 65521ull;
            pc = AD_SHIFT;
        } else if (pc == AD_SHIFT) {
            s = s >> 8;
            pc = AD_INC;
        } else if (pc == AD_INC) {
            i = i + 1ull;
            pc = AD_CHECK;
        } else if (pc == AD_HALT) {
            return (b << 16) | a;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_adler32_64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_adler32_64_loop_target(0xCAFEBABEull));
    return 0;
}
