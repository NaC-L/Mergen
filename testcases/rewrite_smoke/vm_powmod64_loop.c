/* PC-state VM running fast modular exponentiation on uint64_t.
 *   r = 1 % mod
 *   while (exp) {
 *     if (exp & 1) r = (r * base) % mod;
 *     base = (base * base) % mod;
 *     exp >>= 1;
 *   }
 *   return r;
 * Inputs: base in RCX, exp in RDX, mod in R8.  All full uint64_t.
 * Lift target: vm_powmod64_loop_target.
 *
 * Distinct from vm_powermod_loop (i32 powmod): exercises i64 mul +
 * i64 urem inside a variable-trip loop (trip = bit length of exp).
 */
#include <stdio.h>
#include <stdint.h>

enum PmVmPc {
    PM_LOAD       = 0,
    PM_INIT       = 1,
    PM_LOOP_CHECK = 2,
    PM_LOOP_BODY  = 3,
    PM_HALT       = 4,
};

__declspec(noinline)
uint64_t vm_powmod64_loop_target(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t b   = 0;
    uint64_t e   = 0;
    uint64_t m   = 0;
    uint64_t r   = 0;
    int      pc  = PM_LOAD;

    while (1) {
        if (pc == PM_LOAD) {
            b = base;
            e = exp;
            m = mod;
            pc = PM_INIT;
        } else if (pc == PM_INIT) {
            r = 1ull % m;
            pc = PM_LOOP_CHECK;
        } else if (pc == PM_LOOP_CHECK) {
            pc = (e != 0ull) ? PM_LOOP_BODY : PM_HALT;
        } else if (pc == PM_LOOP_BODY) {
            if ((e & 1ull) != 0ull) {
                r = (r * b) % m;
            }
            b = (b * b) % m;
            e = e >> 1;
            pc = PM_LOOP_CHECK;
        } else if (pc == PM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_powmod64(2,10,1000)=%llu vm_powmod64(3,7,100)=%llu\n",
           (unsigned long long)vm_powmod64_loop_target(2ull, 10ull, 1000ull),
           (unsigned long long)vm_powmod64_loop_target(3ull, 7ull, 100ull));
    return 0;
}
