/* PC-state VM with a SIGNED accumulator that adds or subtracts a derived
 * i64 value per iteration, gated by the input bit at the loop counter.
 *   s = 0; n = (x & 0x1F) + 1; base = x | 1;
 *   for i in 0..n:
 *     val = i * base
 *     if (x >> i) & 1:  s += val
 *     else:              s -= val
 *   return s;
 * Lift target: vm_signedaccum64_loop_target.
 *
 * Distinct from vm_condsum64_loop (one-sided gated +) and vm_oddcount64_loop
 * (gated +1): two mutually-exclusive update branches with TWO directions
 * (add vs subtract) on the SAME accumulator slot.  Single counter avoids
 * the dual-i64 pseudo-stack failure documented in vm_dualcounter64.
 */
#include <stdio.h>
#include <stdint.h>

enum SgVmPc {
    SG_LOAD       = 0,
    SG_INIT       = 1,
    SG_LOOP_CHECK = 2,
    SG_LOOP_BODY  = 3,
    SG_LOOP_INC   = 4,
    SG_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_signedaccum64_loop_target(uint64_t x) {
    int      idx  = 0;
    int      n    = 0;
    uint64_t xx   = 0;
    uint64_t base = 0;
    uint64_t s    = 0;
    int      pc   = SG_LOAD;

    while (1) {
        if (pc == SG_LOAD) {
            xx   = x;
            n    = (int)(x & 0x1Full) + 1;
            base = x | 1ull;
            s    = 0ull;
            pc = SG_INIT;
        } else if (pc == SG_INIT) {
            idx = 0;
            pc = SG_LOOP_CHECK;
        } else if (pc == SG_LOOP_CHECK) {
            pc = (idx < n) ? SG_LOOP_BODY : SG_HALT;
        } else if (pc == SG_LOOP_BODY) {
            uint64_t val = (uint64_t)idx * base;
            if (((xx >> idx) & 1ull) != 0ull) {
                s = s + val;
            } else {
                s = s - val;
            }
            pc = SG_LOOP_INC;
        } else if (pc == SG_LOOP_INC) {
            idx = idx + 1;
            pc = SG_LOOP_CHECK;
        } else if (pc == SG_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signedaccum64(0xCAFE)=%llu vm_signedaccum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signedaccum64_loop_target(0xCAFEull),
           (unsigned long long)vm_signedaccum64_loop_target(0xCAFEBABEull));
    return 0;
}
