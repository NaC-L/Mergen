/* PC-state VM that counts how many times an i64 state can be divided
 * by an input-derived divisor before it falls below the divisor.
 *   divisor = (x & 0xFF) + 2;   // 2..257, never zero
 *   state   = ~x;
 *   count   = 0;
 *   while (state >= divisor) { state /= divisor; count++; }
 *   return count;
 * Lift target: vm_divcount64_loop_target.
 *
 * Distinct from vm_gcd64_loop (urem-driven Euclidean): exercises
 * repeated i64 udiv inside a data-dependent loop (variable trip 0..63
 * depending on log_{divisor}(state)).
 */
#include <stdio.h>
#include <stdint.h>

enum DvVmPc {
    DV_LOAD       = 0,
    DV_LOOP_CHECK = 1,
    DV_LOOP_BODY  = 2,
    DV_HALT       = 3,
};

__declspec(noinline)
int vm_divcount64_loop_target(uint64_t x) {
    uint64_t divisor = 0;
    uint64_t state   = 0;
    int      count   = 0;
    int      pc      = DV_LOAD;

    while (1) {
        if (pc == DV_LOAD) {
            divisor = (x & 0xFFull) + 2ull;
            state   = ~x;
            count   = 0;
            pc = DV_LOOP_CHECK;
        } else if (pc == DV_LOOP_CHECK) {
            pc = (state >= divisor) ? DV_LOOP_BODY : DV_HALT;
        } else if (pc == DV_LOOP_BODY) {
            state = state / divisor;
            count = count + 1;
            pc = DV_LOOP_CHECK;
        } else if (pc == DV_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_divcount64(0)=%d vm_divcount64(0xCAFE)=%d\n",
           vm_divcount64_loop_target(0ull),
           vm_divcount64_loop_target(0xCAFEull));
    return 0;
}
