/* PC-state VM running the Collatz sequence on a FULL uint64_t state.
 *   while (state != 1) { state = (state & 1) ? 3*state + 1 : state / 2; count++; }
 * Trip count is data-dependent on the input.  3*x+1 wraps mod 2^64 for
 * very large inputs but Collatz still converges within bounded steps.
 * Lift target: vm_collatz64_loop_target.
 *
 * Distinct from vm_collatz_loop (i32 Collatz): exercises the same
 * algorithm shape on full 64-bit state with i64 udiv (lshr-by-1) and
 * i64 mul-by-3 + add operations.
 */
#include <stdio.h>
#include <stdint.h>

enum C64VmPc {
    C64_LOAD       = 0,
    C64_LOOP_CHECK = 1,
    C64_LOOP_BODY  = 2,
    C64_HALT       = 3,
};

__declspec(noinline)
int vm_collatz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = C64_LOAD;

    while (1) {
        if (pc == C64_LOAD) {
            state = x;
            count = 0;
            pc = C64_LOOP_CHECK;
        } else if (pc == C64_LOOP_CHECK) {
            pc = (state != 1ull) ? C64_LOOP_BODY : C64_HALT;
        } else if (pc == C64_LOOP_BODY) {
            if ((state & 1ull) == 0ull) {
                state = state >> 1;
            } else {
                state = state * 3ull + 1ull;
            }
            count = count + 1;
            pc = C64_LOOP_CHECK;
        } else if (pc == C64_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_collatz64(27)=%d vm_collatz64(0xCAFE)=%d\n",
           vm_collatz64_loop_target(27ull),
           vm_collatz64_loop_target(0xCAFEull));
    return 0;
}
