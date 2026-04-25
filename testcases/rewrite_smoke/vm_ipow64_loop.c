/* PC-state VM running i64 integer-power via square-and-multiply, no
 * modulo.
 *   result = 1; base = x | 1; exp = y & 0xF;
 *   while (exp) { if (exp & 1) result *= base; base *= base; exp >>= 1; }
 *   return result;     // (x|1)^(y&0xF) mod 2^64
 * Lift target: vm_ipow64_loop_target.
 *
 * Distinct from vm_powmod64_loop (urem inside body) and vm_factorial64_loop
 * (linear i*r): exercises i64 mul-only accumulation with conditional
 * gating by exp&1, plus parallel base squaring.
 */
#include <stdio.h>
#include <stdint.h>

enum IpVmPc {
    IP_LOAD       = 0,
    IP_LOOP_CHECK = 1,
    IP_LOOP_BODY  = 2,
    IP_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_ipow64_loop_target(uint64_t x, uint64_t y) {
    uint64_t result = 0;
    uint64_t base   = 0;
    uint64_t exp    = 0;
    int      pc     = IP_LOAD;

    while (1) {
        if (pc == IP_LOAD) {
            result = 1ull;
            base   = x | 1ull;
            exp    = y & 0xFull;
            pc = IP_LOOP_CHECK;
        } else if (pc == IP_LOOP_CHECK) {
            pc = (exp != 0ull) ? IP_LOOP_BODY : IP_HALT;
        } else if (pc == IP_LOOP_BODY) {
            if ((exp & 1ull) != 0ull) {
                result = result * base;
            }
            base = base * base;
            exp = exp >> 1;
            pc = IP_LOOP_CHECK;
        } else if (pc == IP_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_ipow64(2,10)=%llu vm_ipow64(0xCAFE,7)=%llu\n",
           (unsigned long long)vm_ipow64_loop_target(2ull, 10ull),
           (unsigned long long)vm_ipow64_loop_target(0xCAFEull, 7ull));
    return 0;
}
