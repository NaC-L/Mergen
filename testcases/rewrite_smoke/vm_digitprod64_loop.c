/* PC-state VM that computes the product of decimal digits of x.
 *   if (x == 0) return 0;
 *   p = 1;
 *   while (s) { p *= s % 10; s /= 10; }
 *   return p;
 * Variable trip = number of decimal digits.  Returns full uint64_t (low
 * bits dominate; any zero-digit collapses the product to 0).
 * Lift target: vm_digitprod64_loop_target.
 *
 * Distinct from vm_decdigits64_loop (counts digits) and vm_base7sum64_loop
 * (digit SUM in base 7): exercises i64 mul-by-digit accumulator with
 * udiv-by-10 + urem-by-10 inside a data-dependent loop.  Any zero
 * digit forces immediate sticky 0 result.
 */
#include <stdio.h>
#include <stdint.h>

enum DpVmPc {
    DP_LOAD       = 0,
    DP_ZERO_CHECK = 1,
    DP_LOOP_CHECK = 2,
    DP_LOOP_BODY  = 3,
    DP_HALT       = 4,
};

__declspec(noinline)
uint64_t vm_digitprod64_loop_target(uint64_t x) {
    uint64_t s   = 0;
    uint64_t p   = 0;
    int      pc  = DP_LOAD;

    while (1) {
        if (pc == DP_LOAD) {
            s = x;
            p = 1ull;
            pc = DP_ZERO_CHECK;
        } else if (pc == DP_ZERO_CHECK) {
            if (s == 0ull) {
                p = 0ull;
                pc = DP_HALT;
            } else {
                pc = DP_LOOP_CHECK;
            }
        } else if (pc == DP_LOOP_CHECK) {
            pc = (s != 0ull) ? DP_LOOP_BODY : DP_HALT;
        } else if (pc == DP_LOOP_BODY) {
            p = p * (s % 10ull);
            s = s / 10ull;
            pc = DP_LOOP_CHECK;
        } else if (pc == DP_HALT) {
            return p;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_digitprod64(123)=%llu vm_digitprod64(999999999)=%llu\n",
           (unsigned long long)vm_digitprod64_loop_target(123ull),
           (unsigned long long)vm_digitprod64_loop_target(999999999ull));
    return 0;
}
