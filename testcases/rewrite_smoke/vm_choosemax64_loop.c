/* PC-state VM that picks the larger (unsigned) of two derived options
 * per iteration on full uint64_t state.
 *   s = x; n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     opt1 = s * 3 + i
 *     opt2 = s + i*i
 *     s = (opt1 > opt2) ? opt1 : opt2
 *   return s;
 * Lift target: vm_choosemax64_loop_target.
 *
 * Distinct from vm_smax64_loop (signed-max accumulator over derived
 * sequence) and vm_satadd64_loop (overflow-clamp): per-iteration choice
 * between two locally-computed options via icmp ugt + select.
 */
#include <stdio.h>
#include <stdint.h>

enum CmVmPc {
    CM_LOAD       = 0,
    CM_INIT       = 1,
    CM_LOOP_CHECK = 2,
    CM_LOOP_BODY  = 3,
    CM_LOOP_INC   = 4,
    CM_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_choosemax64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t s   = 0;
    int      pc  = CM_LOAD;

    while (1) {
        if (pc == CM_LOAD) {
            s = x;
            n = (int)(x & 0xFull) + 1;
            pc = CM_INIT;
        } else if (pc == CM_INIT) {
            idx = 0;
            pc = CM_LOOP_CHECK;
        } else if (pc == CM_LOOP_CHECK) {
            pc = (idx < n) ? CM_LOOP_BODY : CM_HALT;
        } else if (pc == CM_LOOP_BODY) {
            uint64_t opt1 = s * 3ull + (uint64_t)idx;
            uint64_t opt2 = s + (uint64_t)(idx * idx);
            s = (opt1 > opt2) ? opt1 : opt2;
            pc = CM_LOOP_INC;
        } else if (pc == CM_LOOP_INC) {
            idx = idx + 1;
            pc = CM_LOOP_CHECK;
        } else if (pc == CM_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_choosemax64(0xCAFE)=%llu vm_choosemax64(0xFF)=%llu\n",
           (unsigned long long)vm_choosemax64_loop_target(0xCAFEull),
           (unsigned long long)vm_choosemax64_loop_target(0xFFull));
    return 0;
}
