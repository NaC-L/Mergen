/* PC-state VM that drives a two-state XOR-then-LCG-step accumulator
 * with SUBTRACTIVE LCG increment:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ s;
 *     s = s * 0x9E3779B97F4A7C15 - 1;   // LCG step with SUB increment
 *   }
 *   return r;
 *
 * Lift target: vm_xorrot_substep64_loop_target.
 *
 * Distinct from:
 *   - vm_xorrot64_loop (sister: ADD increment instead of SUB)
 *
 * Same XOR-then-LCG-step shape as vm_xorrot64_loop, but the LCG
 * increment is subtractive.  Tests u64 underflow on the LCG s-update
 * inside an XOR-fold loop.
 */
#include <stdio.h>
#include <stdint.h>

enum XrsVmPc {
    XRS_INIT_ALL = 0,
    XRS_CHECK    = 1,
    XRS_BODY     = 2,
    XRS_INC      = 3,
    XRS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xorrot_substep64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XRS_INIT_ALL;

    while (1) {
        if (pc == XRS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XRS_CHECK;
        } else if (pc == XRS_CHECK) {
            pc = (i < n) ? XRS_BODY : XRS_HALT;
        } else if (pc == XRS_BODY) {
            r = r ^ s;
            s = s * 0x9E3779B97F4A7C15ull - 1ull;
            pc = XRS_INC;
        } else if (pc == XRS_INC) {
            i = i + 1ull;
            pc = XRS_CHECK;
        } else if (pc == XRS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorrot_substep64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xorrot_substep64_loop_target(0xCAFEBABEull));
    return 0;
}
