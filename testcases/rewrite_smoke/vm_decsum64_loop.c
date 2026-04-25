/* PC-state VM that computes the base-10 decimal digit SUM of x.
 *   total = 0;
 *   while (s) { total += s % 10; s /= 10; }
 *   return total;
 * Variable trip = number of decimal digits.
 * Lift target: vm_decsum64_loop_target.
 *
 * Distinct from vm_base7sum64_loop (digit sum base 7) and
 * vm_digitprod64_loop (digit PRODUCT base 10): pure additive digit
 * accumulator with udiv-by-10 + urem-by-10 inside body.  Max value for
 * max u64 is 87 (sum of digits of 18446744073709551615).
 */
#include <stdio.h>
#include <stdint.h>

enum DsVmPc {
    DS_LOAD       = 0,
    DS_LOOP_CHECK = 1,
    DS_LOOP_BODY  = 2,
    DS_HALT       = 3,
};

__declspec(noinline)
int vm_decsum64_loop_target(uint64_t x) {
    uint64_t s     = 0;
    int      total = 0;
    int      pc    = DS_LOAD;

    while (1) {
        if (pc == DS_LOAD) {
            s     = x;
            total = 0;
            pc = DS_LOOP_CHECK;
        } else if (pc == DS_LOOP_CHECK) {
            pc = (s != 0ull) ? DS_LOOP_BODY : DS_HALT;
        } else if (pc == DS_LOOP_BODY) {
            total = total + (int)(s % 10ull);
            s = s / 10ull;
            pc = DS_LOOP_CHECK;
        } else if (pc == DS_HALT) {
            return total;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_decsum64(12345)=%d vm_decsum64(max)=%d\n",
           vm_decsum64_loop_target(12345ull),
           vm_decsum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
