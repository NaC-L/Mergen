/* PC-state VM that applies the Murmur3 64-bit finalizer n times in a row:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) {
 *     r ^= r >> 33;
 *     r *= 0xFF51AFD7ED558CCD;
 *     r ^= r >> 33;
 *     r *= 0xC4CEB9FE1A85EC53;
 *   }
 *   // (no trailing fold here, so r is the cycled state)
 *   return r;
 *
 * Lift target: vm_fmix_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_fmix64_loop      (single fmix application, no loop)
 *   - vm_xxhmix64_loop    (per-byte mix; one mul; xor-fold OUTSIDE loop)
 *   - vm_murmurstep64_loop (single magic; xor-with-input each iter)
 *   - vm_splitmix64_loop  (different magics; constant additive step)
 *
 * Tests dual-magic xor-mul-xor-mul finalizer chain inside a counter
 * loop body.  Each iteration applies four sequential ops on a single
 * i64 accumulator: lshr-33 + xor, mul-by-magic1, lshr-33 + xor,
 * mul-by-magic2.  Single-state, no byte windowing.
 */
#include <stdio.h>
#include <stdint.h>

enum FxVmPc {
    FX_INIT_ALL = 0,
    FX_CHECK    = 1,
    FX_BODY     = 2,
    FX_INC      = 3,
    FX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_fmix_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = FX_INIT_ALL;

    while (1) {
        if (pc == FX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = FX_CHECK;
        } else if (pc == FX_CHECK) {
            pc = (i < n) ? FX_BODY : FX_HALT;
        } else if (pc == FX_BODY) {
            r = r ^ (r >> 33);
            r = r * 0xFF51AFD7ED558CCDull;
            r = r ^ (r >> 33);
            r = r * 0xC4CEB9FE1A85EC53ull;
            pc = FX_INC;
        } else if (pc == FX_INC) {
            i = i + 1ull;
            pc = FX_CHECK;
        } else if (pc == FX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fmix_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fmix_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
