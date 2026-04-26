/* PC-state VM running a Marsaglia-style three-shift xorshift with
 * REVERSED shift directions:
 *
 *   n     = (x & 7) + 1;
 *   state = x | 1;                          // avoid all-zero state
 *   for (i = 0; i < n; i++) {
 *     state ^= state >> 13;                 // R instead of L
 *     state ^= state << 7;                  // L instead of R
 *     state ^= state >> 17;                 // R instead of L
 *   }
 *   return state;
 *
 * Lift target: vm_xorshift_rev64_loop_target.
 *
 * Distinct from:
 *   - vm_xorshift64_loop  (sister: L13, R7, L17 instead of R13, L7, R17)
 *
 * Same Marsaglia three-shift xorshift PRNG shape; opposite shift
 * direction sequence.  Tests the lifter's lshr/shl pattern handling
 * with the directions swapped.
 */
#include <stdio.h>
#include <stdint.h>

enum XsrVmPc {
    XSR_INIT_ALL    = 0,
    XSR_LOOP_CHECK  = 1,
    XSR_LOOP_BODY   = 2,
    XSR_LOOP_INC    = 3,
    XSR_HALT        = 4,
};

__declspec(noinline)
uint64_t vm_xorshift_rev64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t state = 0;
    uint64_t idx   = 0;
    int      pc    = XSR_INIT_ALL;

    while (1) {
        if (pc == XSR_INIT_ALL) {
            n     = (x & 7ull) + 1ull;
            state = x | 1ull;
            idx   = 0ull;
            pc    = XSR_LOOP_CHECK;
        } else if (pc == XSR_LOOP_CHECK) {
            pc = (idx < n) ? XSR_LOOP_BODY : XSR_HALT;
        } else if (pc == XSR_LOOP_BODY) {
            state = state ^ (state >> 13);
            state = state ^ (state << 7);
            state = state ^ (state >> 17);
            pc = XSR_LOOP_INC;
        } else if (pc == XSR_LOOP_INC) {
            idx = idx + 1;
            pc = XSR_LOOP_CHECK;
        } else if (pc == XSR_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorshift_rev64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xorshift_rev64_loop_target(0xCAFEBABEull));
    return 0;
}
