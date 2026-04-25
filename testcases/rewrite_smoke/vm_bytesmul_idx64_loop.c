/* PC-state VM that accumulates each signed byte of x times its
 * 1-based loop index over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     r += (int64_t)sb * (int64_t)(i + 1);
 *     s >>= 8;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_bytesmul_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop  (sext bytes, no index multiplier)
 *   - vm_altbytesum64_loop     (alternating fixed sign, no multiplier)
 *   - vm_squareadd64_loop      (single quadratic recurrence on whole x)
 *
 * Tests sext-i8 byte multiplied by i+1 (i is loop-index phi) chained
 * into a signed accumulator that round-trips through u64.  The
 * (i+1) factor exercises i64 multiply against a dynamic counter
 * value rather than a constant.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_INC      = 3,
    BS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytesmul_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (i < n) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            r = r + (int64_t)sb * (int64_t)(i + 1ull);
            s = s >> 8;
            pc = BS_INC;
        } else if (pc == BS_INC) {
            i = i + 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytesmul_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_bytesmul_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
