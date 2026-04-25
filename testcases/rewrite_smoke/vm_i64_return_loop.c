/* PC-state VM that returns a FULL uint64_t, not the typical i32-narrowed
 * result.  Runs a Knuth-mixer recurrence
 *   state = state * 0x9E3779B97F4A7C15 + i
 * for n = (x & 7) + 1 iterations starting from state = x.
 * Lift target: vm_i64_return_loop_target.
 *
 * Distinct from existing i64 samples (vm_int64_loop / vm_shift64_loop /
 * vm_u64_array_loop) which mask to i32 at the return boundary; here the
 * lifted function's i64 return is the actual semantic value, exercising
 * the full 64-bit return-value path through the lifter.
 */
#include <stdio.h>
#include <stdint.h>

enum I64rVmPc {
    I64R_LOAD       = 0,
    I64R_INIT       = 1,
    I64R_LOOP_CHECK = 2,
    I64R_LOOP_BODY  = 3,
    I64R_LOOP_INC   = 4,
    I64R_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_i64_return_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = I64R_LOAD;

    while (1) {
        if (pc == I64R_LOAD) {
            n     = (int)(x & 7u) + 1;
            state = x;
            pc = I64R_INIT;
        } else if (pc == I64R_INIT) {
            idx = 0;
            pc = I64R_LOOP_CHECK;
        } else if (pc == I64R_LOOP_CHECK) {
            pc = (idx < n) ? I64R_LOOP_BODY : I64R_HALT;
        } else if (pc == I64R_LOOP_BODY) {
            state = state * 0x9E3779B97F4A7C15ull + (uint64_t)idx;
            pc = I64R_LOOP_INC;
        } else if (pc == I64R_LOOP_INC) {
            idx = idx + 1;
            pc = I64R_LOOP_CHECK;
        } else if (pc == I64R_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_i64_return(1)=0x%llx vm_i64_return(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_i64_return_loop_target(1ull),
           (unsigned long long)vm_i64_return_loop_target(0xCAFEull));
    return 0;
}
