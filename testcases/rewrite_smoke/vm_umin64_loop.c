/* PC-state VM running an i64 UNSIGNED-min reduction over a derived
 * sequence.
 *   n = (x & 0x1F) + 1;
 *   m = MAX_U64;
 *   for i in 0..n: { val = x ^ (i * K_golden); if (val < m) m = val; }
 *   return m;
 * Lift target: vm_umin64_loop_target.
 *
 * Distinct from vm_smax64_loop (signed-max via icmp sgt) and
 * vm_choosemax64_loop (per-iter ternary on fresh options): exercises
 * unsigned-min reduction via icmp ult + conditional-update accumulator.
 */
#include <stdio.h>
#include <stdint.h>

enum UmVmPc {
    UM_LOAD       = 0,
    UM_INIT       = 1,
    UM_LOOP_CHECK = 2,
    UM_LOOP_BODY  = 3,
    UM_LOOP_INC   = 4,
    UM_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_umin64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t m   = 0;
    int      pc  = UM_LOAD;

    while (1) {
        if (pc == UM_LOAD) {
            n  = (int)(x & 0x1Full) + 1;
            xx = x;
            m  = 0xFFFFFFFFFFFFFFFFull;
            pc = UM_INIT;
        } else if (pc == UM_INIT) {
            idx = 0;
            pc = UM_LOOP_CHECK;
        } else if (pc == UM_LOOP_CHECK) {
            pc = (idx < n) ? UM_LOOP_BODY : UM_HALT;
        } else if (pc == UM_LOOP_BODY) {
            uint64_t val = xx ^ ((uint64_t)idx * 0x9E3779B97F4A7C15ull);
            if (val < m) {
                m = val;
            }
            pc = UM_LOOP_INC;
        } else if (pc == UM_LOOP_INC) {
            idx = idx + 1;
            pc = UM_LOOP_CHECK;
        } else if (pc == UM_HALT) {
            return m;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_umin64(0xCAFE)=%llu vm_umin64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_umin64_loop_target(0xCAFEull),
           (unsigned long long)vm_umin64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
