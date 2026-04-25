/* PC-state VM that counts decimal digits of a uint64_t via repeated /10.
 *   if (x == 0) return 1;
 *   count = 0;
 *   while (state > 0) { state /= 10; count++; }
 *   return count;
 * Variable trip 1..20 (up to 20 for max u64).
 * Lift target: vm_decdigits64_loop_target.
 *
 * Distinct from vm_divcount64_loop (input-derived divisor with >=
 * comparison) and vm_sdiv64_loop: this uses a fixed constant divisor 10
 * with a > 0 termination, exercising i64 udiv-by-constant inside a
 * data-dependent loop.  Lifter likely emits magic-number multiplication
 * fold for /10, but loop count remains data-dependent.
 */
#include <stdio.h>
#include <stdint.h>

enum DdVmPc {
    DD_LOAD       = 0,
    DD_ZERO_CHECK = 1,
    DD_LOOP_CHECK = 2,
    DD_LOOP_BODY  = 3,
    DD_HALT       = 4,
};

__declspec(noinline)
int vm_decdigits64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = DD_LOAD;

    while (1) {
        if (pc == DD_LOAD) {
            state = x;
            count = 0;
            pc = DD_ZERO_CHECK;
        } else if (pc == DD_ZERO_CHECK) {
            if (state == 0ull) {
                count = 1;
                pc = DD_HALT;
            } else {
                pc = DD_LOOP_CHECK;
            }
        } else if (pc == DD_LOOP_CHECK) {
            pc = (state > 0ull) ? DD_LOOP_BODY : DD_HALT;
        } else if (pc == DD_LOOP_BODY) {
            state = state / 10ull;
            count = count + 1;
            pc = DD_LOOP_CHECK;
        } else if (pc == DD_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_decdigits64(0xCAFEBABE)=%d vm_decdigits64(max)=%d\n",
           vm_decdigits64_loop_target(0xCAFEBABEull),
           vm_decdigits64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
