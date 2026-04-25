/* PC-state VM running an i64 count-leading-zeros via shift-loop.
 *   if (x == 0) return 64;
 *   count = 0;
 *   while ((x & 0x8000000000000000) == 0) { x <<= 1; count++; }
 *   return count;
 * Variable trip 0..63 (or short-circuit 64 for zero).
 * Lift target: vm_clz64_loop_target.
 *
 * Companion to vm_cttz64_loop (which counts trailing zeros via shift-right).
 * Distinct from vm_imported_clz_loop (i32 _BitScanReverse intrinsic):
 * exercises explicit shift-left + MSB-test on full i64 in a variable-trip loop.
 */
#include <stdio.h>
#include <stdint.h>

enum ClVmPc {
    CL_LOAD       = 0,
    CL_INIT       = 1,
    CL_ZERO_CHECK = 2,
    CL_LOOP_CHECK = 3,
    CL_LOOP_BODY  = 4,
    CL_HALT       = 5,
};

__declspec(noinline)
int vm_clz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = CL_LOAD;

    while (1) {
        if (pc == CL_LOAD) {
            state = x;
            count = 0;
            pc = CL_ZERO_CHECK;
        } else if (pc == CL_ZERO_CHECK) {
            if (state == 0ull) {
                count = 64;
                pc = CL_HALT;
            } else {
                pc = CL_LOOP_CHECK;
            }
        } else if (pc == CL_LOOP_CHECK) {
            pc = ((state & 0x8000000000000000ull) == 0ull) ? CL_LOOP_BODY : CL_HALT;
        } else if (pc == CL_LOOP_BODY) {
            state = state << 1;
            count = count + 1;
            pc = CL_LOOP_CHECK;
        } else if (pc == CL_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_clz64(1)=%d vm_clz64(0x8000000000000000)=%d\n",
           vm_clz64_loop_target(1ull),
           vm_clz64_loop_target(0x8000000000000000ull));
    return 0;
}
