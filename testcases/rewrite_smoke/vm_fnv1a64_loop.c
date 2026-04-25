/* PC-state VM running an FNV-1a hash chain over n = (x & 7) + 1 bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xCBF29CE484222325;   // FNV offset basis
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFF)) * 0x100000001B3ull;   // FNV prime
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv1a64_loop_target.
 *
 * Distinct from:
 *   - vm_djb264_loop      (additive *33 hash, chained add+mul)
 *   - vm_murmurstep64_loop (xor-input then mul-magic then xor-fold; same
 *     input each iter)
 *   - vm_horner64_loop    (polynomial evaluation)
 *
 * Differs from Murmur in two ways: FNV consumes a different byte each
 * iteration (windowed via shift on s) and the loop body is the
 * canonical FNV-1a step xor-then-multiply-by-prime, with no folding
 * shift afterwards.  Tests byte masking, xor-with-state, and i64
 * multiply by a 40-bit prime threaded through a counter-bound loop.
 */
#include <stdio.h>
#include <stdint.h>

enum FvVmPc {
    FV_INIT_ALL = 0,
    FV_CHECK    = 1,
    FV_HASH     = 2,
    FV_SHIFT    = 3,
    FV_INC      = 4,
    FV_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv1a64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = FV_INIT_ALL;

    while (1) {
        if (pc == FV_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = FV_CHECK;
        } else if (pc == FV_CHECK) {
            pc = (i < n) ? FV_HASH : FV_HALT;
        } else if (pc == FV_HASH) {
            r = (r ^ (s & 0xFFull)) * 0x100000001B3ull;
            pc = FV_SHIFT;
        } else if (pc == FV_SHIFT) {
            s = s >> 8;
            pc = FV_INC;
        } else if (pc == FV_INC) {
            i = i + 1ull;
            pc = FV_CHECK;
        } else if (pc == FV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv1a64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fnv1a64_loop_target(0xCAFEBABEull));
    return 0;
}
