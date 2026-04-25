/* PC-state VM that reverses the decimal digits of x.
 *   r = 0; s = x;
 *   while (s) { r = r * 10 + (s % 10); s /= 10; }
 *   return r;
 * Variable trip = number of decimal digits.  Returns full uint64_t
 * (very large inputs reverse to wraparound values).
 * Lift target: vm_revdecimal64_loop_target.
 *
 * Distinct from vm_digitprod64_loop (multiplies digits) and
 * vm_decdigits64_loop (counts digits): per-iter mul-by-10 + add-mod-10
 * + div-by-10 chain that reconstructs the reversed number digit by
 * digit.  Tests three i64 ops (mul, urem, udiv) against constant 10
 * inside the same loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum RvVmPc {
    RV_LOAD       = 0,
    RV_LOOP_CHECK = 1,
    RV_LOOP_BODY  = 2,
    RV_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_revdecimal64_loop_target(uint64_t x) {
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = RV_LOAD;

    while (1) {
        if (pc == RV_LOAD) {
            s = x;
            r = 0ull;
            pc = RV_LOOP_CHECK;
        } else if (pc == RV_LOOP_CHECK) {
            pc = (s != 0ull) ? RV_LOOP_BODY : RV_HALT;
        } else if (pc == RV_LOOP_BODY) {
            r = r * 10ull + (s % 10ull);
            s = s / 10ull;
            pc = RV_LOOP_CHECK;
        } else if (pc == RV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_revdecimal64(12345)=%llu vm_revdecimal64(1234567890)=%llu\n",
           (unsigned long long)vm_revdecimal64_loop_target(12345ull),
           (unsigned long long)vm_revdecimal64_loop_target(1234567890ull));
    return 0;
}
