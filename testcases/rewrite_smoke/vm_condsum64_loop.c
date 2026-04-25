/* PC-state VM that conditionally sums values (only when the value is
 * odd) over a derived sequence.
 *   s = 0; n = (x & 0x1F) + 1;
 *   for i in 0..n:
 *     val = x + i * K_golden
 *     if (val & 1) s = s + val
 *   return s;
 * Lift target: vm_condsum64_loop_target.
 *
 * Distinct from vm_smax64_loop (always-update via icmp sgt) and
 * vm_satadd64_loop (overflow-clamp): the body GATES the accumulator
 * on a parity bit-test, so some iterations contribute zero.
 */
#include <stdio.h>
#include <stdint.h>

enum CsVmPc {
    CS_LOAD       = 0,
    CS_INIT       = 1,
    CS_LOOP_CHECK = 2,
    CS_LOOP_BODY  = 3,
    CS_LOOP_INC   = 4,
    CS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_condsum64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = CS_LOAD;

    while (1) {
        if (pc == CS_LOAD) {
            xx = x;
            n  = (int)(x & 0x1Full) + 1;
            s  = 0ull;
            pc = CS_INIT;
        } else if (pc == CS_INIT) {
            idx = 0;
            pc = CS_LOOP_CHECK;
        } else if (pc == CS_LOOP_CHECK) {
            pc = (idx < n) ? CS_LOOP_BODY : CS_HALT;
        } else if (pc == CS_LOOP_BODY) {
            uint64_t val = xx + (uint64_t)idx * 0x9E3779B97F4A7C15ull;
            if ((val & 1ull) != 0ull) {
                s = s + val;
            }
            pc = CS_LOOP_INC;
        } else if (pc == CS_LOOP_INC) {
            idx = idx + 1;
            pc = CS_LOOP_CHECK;
        } else if (pc == CS_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_condsum64(0xCAFE)=%llu vm_condsum64(0xFF)=%llu\n",
           (unsigned long long)vm_condsum64_loop_target(0xCAFEull),
           (unsigned long long)vm_condsum64_loop_target(0xFFull));
    return 0;
}
