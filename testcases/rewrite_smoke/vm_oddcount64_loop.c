/* PC-state VM that counts how many values in a derived sequence are odd.
 *   count = 0; n = (x & 0x1F) + 1;
 *   for i in 0..n:
 *     val = x + i * K_golden
 *     if (val & 1): count++
 *   return count;
 * Returns count as i64 (low bits only).
 * Lift target: vm_oddcount64_loop_target.
 *
 * Distinct from vm_condsum64_loop (gated SUM accumulator on full i64
 * values) and the failed vm_dualcounter64_loop (two i64 counters cause
 * pseudo-stack promotion failure): single integer counter, gated by
 * parity bit-test, body uses i64 mul + add to compute val.
 */
#include <stdio.h>
#include <stdint.h>

enum OcVmPc {
    OC_LOAD       = 0,
    OC_INIT       = 1,
    OC_LOOP_CHECK = 2,
    OC_LOOP_BODY  = 3,
    OC_LOOP_INC   = 4,
    OC_HALT       = 5,
};

__declspec(noinline)
int vm_oddcount64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t xx    = 0;
    int      count = 0;
    int      pc    = OC_LOAD;

    while (1) {
        if (pc == OC_LOAD) {
            xx    = x;
            n     = (int)(x & 0x1Full) + 1;
            count = 0;
            pc = OC_INIT;
        } else if (pc == OC_INIT) {
            idx = 0;
            pc = OC_LOOP_CHECK;
        } else if (pc == OC_LOOP_CHECK) {
            pc = (idx < n) ? OC_LOOP_BODY : OC_HALT;
        } else if (pc == OC_LOOP_BODY) {
            uint64_t val = xx + (uint64_t)idx * 0x9E3779B97F4A7C15ull;
            if ((val & 1ull) != 0ull) {
                count = count + 1;
            }
            pc = OC_LOOP_INC;
        } else if (pc == OC_LOOP_INC) {
            idx = idx + 1;
            pc = OC_LOOP_CHECK;
        } else if (pc == OC_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_oddcount64(0xCAFE)=%d vm_oddcount64(0x1F)=%d\n",
           vm_oddcount64_loop_target(0xCAFEull),
           vm_oddcount64_loop_target(0x1Full));
    return 0;
}
