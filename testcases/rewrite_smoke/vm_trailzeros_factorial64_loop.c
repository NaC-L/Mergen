/* PC-state VM that computes the number of trailing zeros in n!  via
 * Legendre's formula:  c = floor(n/5) + floor(n/25) + floor(n/125) + ...
 *
 *   s = n; c = 0;
 *   while (s) { s /= 5; c += s; }
 *   return c;
 *
 * Variable trip = log_5(n).  Returns full uint64_t.
 * Lift target: vm_trailzeros_factorial64_loop_target.
 *
 * Distinct from vm_decsum64_loop / vm_revdecimal64_loop (divide-by-10)
 * and vm_digitprod64_loop (multiply digits).  Tests udiv-by-5
 * (different magic number) inside data-dependent loop where each
 * iteration adds the running quotient (not the remainder) to the
 * accumulator.  This is the classical Legendre trailing-zero formula.
 */
#include <stdio.h>
#include <stdint.h>

enum TzVmPc {
    TZ_LOAD       = 0,
    TZ_LOOP_CHECK = 1,
    TZ_LOOP_BODY  = 2,
    TZ_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_trailzeros_factorial64_loop_target(uint64_t n) {
    uint64_t s = 0;
    uint64_t c = 0;
    int      pc = TZ_LOAD;

    while (1) {
        if (pc == TZ_LOAD) {
            s = n;
            c = 0ull;
            pc = TZ_LOOP_CHECK;
        } else if (pc == TZ_LOOP_CHECK) {
            pc = (s != 0ull) ? TZ_LOOP_BODY : TZ_HALT;
        } else if (pc == TZ_LOOP_BODY) {
            s = s / 5ull;
            c = c + s;
            pc = TZ_LOOP_CHECK;
        } else if (pc == TZ_HALT) {
            return c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_tz_fact(100)=%llu vm_tz_fact(1000000)=%llu\n",
           (unsigned long long)vm_trailzeros_factorial64_loop_target(100ull),
           (unsigned long long)vm_trailzeros_factorial64_loop_target(1000000ull));
    return 0;
}
