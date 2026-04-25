/* PC-state VM running the bit-by-bit integer-square-root algorithm on
 * full uint64_t.  Fixed-trip 32-iteration loop (bit walks from 2^62
 * down to 2^0 in steps of 4).  Returns floor(sqrt(x)) as full uint64_t.
 *
 *   res = 0; bit = 1<<62;
 *   while (bit) {
 *     if (x >= res + bit) { x -= res + bit; res = (res >> 1) + bit; }
 *     else                 { res >>= 1; }
 *     bit >>= 2;
 *   }
 *   return res;
 *
 * Lift target: vm_isqrt64_loop_target.
 *
 * Distinct from vm_isqrt_loop (i32 isqrt): exercises the same shape on
 * full 64-bit state with a 32-trip fixed-bound loop containing branchy
 * accumulator updates.
 */
#include <stdio.h>
#include <stdint.h>

enum SqVmPc {
    SQ_LOAD       = 0,
    SQ_LOOP_CHECK = 1,
    SQ_LOOP_BODY  = 2,
    SQ_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_isqrt64_loop_target(uint64_t x) {
    uint64_t state = 0;
    uint64_t res   = 0;
    uint64_t bit   = 0;
    int      pc    = SQ_LOAD;

    while (1) {
        if (pc == SQ_LOAD) {
            state = x;
            res   = 0ull;
            bit   = 1ull << 62;
            pc = SQ_LOOP_CHECK;
        } else if (pc == SQ_LOOP_CHECK) {
            pc = (bit != 0ull) ? SQ_LOOP_BODY : SQ_HALT;
        } else if (pc == SQ_LOOP_BODY) {
            if (state >= res + bit) {
                state = state - (res + bit);
                res   = (res >> 1) + bit;
            } else {
                res = res >> 1;
            }
            bit = bit >> 2;
            pc = SQ_LOOP_CHECK;
        } else if (pc == SQ_HALT) {
            return res;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_isqrt64(10000)=%llu vm_isqrt64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_isqrt64_loop_target(10000ull),
           (unsigned long long)vm_isqrt64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
