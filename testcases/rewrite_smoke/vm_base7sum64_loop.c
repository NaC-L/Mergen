/* PC-state VM that computes the base-7 digit sum of x via repeated
 * urem-then-udiv.
 *   total = 0;
 *   while (s) { total += s % 7; s /= 7; }
 *   return total;
 * Variable trip ~= log_7(x).
 * Lift target: vm_base7sum64_loop_target.
 *
 * Distinct from vm_decdigits64_loop (counts digits, divisor 10) and
 * vm_divcount64_loop (input-derived divisor): exercises BOTH urem and
 * udiv by a small constant 7 inside the same loop body, accumulating
 * the running digit sum.
 */
#include <stdio.h>
#include <stdint.h>

enum B7VmPc {
    B7_LOAD       = 0,
    B7_LOOP_CHECK = 1,
    B7_LOOP_BODY  = 2,
    B7_HALT       = 3,
};

__declspec(noinline)
int vm_base7sum64_loop_target(uint64_t x) {
    uint64_t s     = 0;
    int      total = 0;
    int      pc    = B7_LOAD;

    while (1) {
        if (pc == B7_LOAD) {
            s     = x;
            total = 0;
            pc = B7_LOOP_CHECK;
        } else if (pc == B7_LOOP_CHECK) {
            pc = (s != 0ull) ? B7_LOOP_BODY : B7_HALT;
        } else if (pc == B7_LOOP_BODY) {
            total = total + (int)(s % 7ull);
            s = s / 7ull;
            pc = B7_LOOP_CHECK;
        } else if (pc == B7_HALT) {
            return total;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_base7sum64(0xCAFEBABE)=%d vm_base7sum64(max)=%d\n",
           vm_base7sum64_loop_target(0xCAFEBABEull),
           vm_base7sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
