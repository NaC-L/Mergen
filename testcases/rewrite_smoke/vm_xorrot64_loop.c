/* PC-state VM that drives a two-state XOR-then-LCG-step accumulator:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ s;
 *     s = s * 0x9E3779B97F4A7C15 + 1;   // LCG step (golden-ratio mul)
 *   }
 *   return r;
 *
 * Lift target: vm_xorrot64_loop_target  (name kept for manifest stability).
 *
 * Distinct from:
 *   - vm_lfsr64_loop (LFSR with feedback bit)
 *   - vm_pcg64_loop  (PCG random)
 *   - vm_xorshift64_loop (Marsaglia three-shift xorshift)
 *
 * Initial attempt used an i64 rotate (rotl s,7) inside the body but
 * the lifter collapsed the rotate to a single fshl outside the loop
 * and the body became an infinite XOR against a constant.  Replacing
 * with an arithmetic LCG step (multiply + add) preserves live state
 * across iterations.
 */
#include <stdio.h>
#include <stdint.h>

enum XrVmPc {
    XR_INIT_ALL = 0,
    XR_CHECK    = 1,
    XR_ACC      = 2,
    XR_STEP     = 3,
    XR_INC      = 4,
    XR_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_xorrot64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XR_INIT_ALL;

    while (1) {
        if (pc == XR_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XR_CHECK;
        } else if (pc == XR_CHECK) {
            pc = (i < n) ? XR_ACC : XR_HALT;
        } else if (pc == XR_ACC) {
            r = r ^ s;
            pc = XR_STEP;
        } else if (pc == XR_STEP) {
            s = s * 0x9E3779B97F4A7C15ull + 1ull;
            pc = XR_INC;
        } else if (pc == XR_INC) {
            i = i + 1ull;
            pc = XR_CHECK;
        } else if (pc == XR_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorrot64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xorrot64_loop_target(0xCAFEBABEull));
    return 0;
}
