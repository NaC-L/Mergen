/* PC-state VM that runs Horner-style hash with multiplier 3:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r * 3 + (s & 0xFF);
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_mul3byte_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_djb264_loop          (multiplier *33 hash)
 *   - vm_fnv1a64_loop         (multiplier *FNV_PRIME after xor)
 *   - vm_horner64_loop        (general polynomial)
 *   - vm_xormuladd_chain64_loop (mul + xor + add, different ops)
 *
 * Tests `mul i64 r, 3` (small-constant multiplier - lifter likely
 * keeps as raw mul rather than lea-by-3 or shift+add fold).  Each
 * iter: multiply by 3 then add the next byte.  Variant on the
 * Horner polynomial evaluation pattern with a non-power-of-2
 * coefficient.
 */
#include <stdio.h>
#include <stdint.h>

enum M3VmPc {
    M3_INIT_ALL = 0,
    M3_CHECK    = 1,
    M3_BODY     = 2,
    M3_INC      = 3,
    M3_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_mul3byte_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = M3_INIT_ALL;

    while (1) {
        if (pc == M3_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = M3_CHECK;
        } else if (pc == M3_CHECK) {
            pc = (i < n) ? M3_BODY : M3_HALT;
        } else if (pc == M3_BODY) {
            r = r * 3ull + (s & 0xFFull);
            s = s >> 8;
            pc = M3_INC;
        } else if (pc == M3_INC) {
            i = i + 1ull;
            pc = M3_CHECK;
        } else if (pc == M3_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_mul3byte_chain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_mul3byte_chain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
