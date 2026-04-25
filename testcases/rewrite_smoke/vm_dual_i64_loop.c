/* PC-state VM with TWO full uint64_t inputs (x in RCX, y in RDX).
 * Runs state = state * y + x for n = (x & 7) + 1 iterations starting
 * from state = x ^ y, returning the full uint64_t state.
 * Lift target: vm_dual_i64_loop_target.
 *
 * Distinct from vm_mixed_args_loop (i32+i64) and vm_two_input_loop
 * (i32+i32): here BOTH arguments are full 64-bit live across the loop
 * body, with a 64-bit return.  Exercises the lifter's 64-bit register
 * tracking for both RCX and RDX simultaneously.
 */
#include <stdio.h>
#include <stdint.h>

enum DqVmPc {
    DQ_LOAD       = 0,
    DQ_INIT       = 1,
    DQ_LOOP_CHECK = 2,
    DQ_LOOP_BODY  = 3,
    DQ_LOOP_INC   = 4,
    DQ_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_dual_i64_loop_target(uint64_t x, uint64_t y) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    uint64_t xx    = 0;
    uint64_t yy    = 0;
    int      pc    = DQ_LOAD;

    while (1) {
        if (pc == DQ_LOAD) {
            n     = (int)(x & 7ull) + 1;
            xx    = x;
            yy    = y;
            state = x ^ y;
            pc = DQ_INIT;
        } else if (pc == DQ_INIT) {
            idx = 0;
            pc = DQ_LOOP_CHECK;
        } else if (pc == DQ_LOOP_CHECK) {
            pc = (idx < n) ? DQ_LOOP_BODY : DQ_HALT;
        } else if (pc == DQ_LOOP_BODY) {
            state = state * yy + xx;
            pc = DQ_LOOP_INC;
        } else if (pc == DQ_LOOP_INC) {
            idx = idx + 1;
            pc = DQ_LOOP_CHECK;
        } else if (pc == DQ_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dual_i64(7,11)=0x%llx vm_dual_i64(0xCAFE,0xBABE)=0x%llx\n",
           (unsigned long long)vm_dual_i64_loop_target(7ull, 11ull),
           (unsigned long long)vm_dual_i64_loop_target(0xCAFEull, 0xBABEull));
    return 0;
}
