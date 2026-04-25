/* PC-state VM that accumulates a geometric series 1 + 3 + 9 + ... + 3^(n-1)
 * over n = (x & 15) + 1 iterations, with everything in u64 arithmetic
 * (matters once 3^k overflows beyond n=15).
 *
 *   n = (x & 15) + 1;
 *   r = 0; p = 1;
 *   while (n) { r += p; p *= 3; n--; }
 *   return r;
 *
 * Lift target: vm_geosum64_loop_target.
 *
 * Distinct from vm_fibonacci_loop (additive a,b two-state) and from
 * vm_powmod64 (modular exponentiation).  Two-state (r, p) where p is
 * MULTIPLIED by a constant each iteration and r accumulates p.  Same
 * counter-bound shape as fibonacci_loop so the lifter generalizes the
 * loop, but the body exercises i64 multiply-by-3 and add chained.
 */
#include <stdio.h>
#include <stdint.h>

enum GsVmPc {
    GS_LOAD_N    = 0,
    GS_INIT_REGS = 1,
    GS_CHECK     = 2,
    GS_ACC       = 3,
    GS_SCALE     = 4,
    GS_DEC       = 5,
    GS_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_geosum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t r = 0;
    uint64_t p = 0;
    int      pc = GS_LOAD_N;

    while (1) {
        if (pc == GS_LOAD_N) {
            n = (x & 15ull) + 1ull;
            pc = GS_INIT_REGS;
        } else if (pc == GS_INIT_REGS) {
            r = 0ull;
            p = 1ull;
            pc = GS_CHECK;
        } else if (pc == GS_CHECK) {
            pc = (n > 0ull) ? GS_ACC : GS_HALT;
        } else if (pc == GS_ACC) {
            r = r + p;
            pc = GS_SCALE;
        } else if (pc == GS_SCALE) {
            p = p * 3ull;
            pc = GS_DEC;
        } else if (pc == GS_DEC) {
            n = n - 1ull;
            pc = GS_CHECK;
        } else if (pc == GS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_geosum64(7)=%llu vm_geosum64(15)=%llu\n",
           (unsigned long long)vm_geosum64_loop_target(7ull),
           (unsigned long long)vm_geosum64_loop_target(15ull));
    return 0;
}
