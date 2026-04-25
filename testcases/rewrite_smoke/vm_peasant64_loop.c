/* PC-state VM running Russian-peasant (shift-and-add) multiplication
 * on full uint64_t.
 *   r = 0; a = x; b = y;
 *   while (b) { if (b & 1) r += a; a <<= 1; b >>= 1; }
 *   return r;     // (a*b) mod 2^64
 * Variable trip = bit length of b (1..64).  Inputs in RCX, RDX.
 * Lift target: vm_peasant64_loop_target.
 *
 * Distinct from existing i64 mul samples (vm_dual_i64_loop / vm_pcg64_loop):
 * exercises explicit shift-and-add multiply with conditional accumulate
 * inside a data-dependent loop, rather than direct mul i64.
 */
#include <stdio.h>
#include <stdint.h>

enum PvVmPc {
    PV_LOAD       = 0,
    PV_LOOP_CHECK = 1,
    PV_LOOP_BODY  = 2,
    PV_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_peasant64_loop_target(uint64_t x, uint64_t y) {
    uint64_t a = 0;
    uint64_t b = 0;
    uint64_t r = 0;
    int      pc = PV_LOAD;

    while (1) {
        if (pc == PV_LOAD) {
            a = x;
            b = y;
            r = 0ull;
            pc = PV_LOOP_CHECK;
        } else if (pc == PV_LOOP_CHECK) {
            pc = (b != 0ull) ? PV_LOOP_BODY : PV_HALT;
        } else if (pc == PV_LOOP_BODY) {
            if ((b & 1ull) != 0ull) {
                r = r + a;
            }
            a = a << 1;
            b = b >> 1;
            pc = PV_LOOP_CHECK;
        } else if (pc == PV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_peasant64(11,13)=%llu vm_peasant64(0xCAFE,0xBABE)=%llu\n",
           (unsigned long long)vm_peasant64_loop_target(11ull, 13ull),
           (unsigned long long)vm_peasant64_loop_target(0xCAFEull, 0xBABEull));
    return 0;
}
