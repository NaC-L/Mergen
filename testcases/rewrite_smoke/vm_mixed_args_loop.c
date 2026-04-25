/* PC-state VM with MIXED-WIDTH input parameters: int x in RCX, full
 * uint64_t y in RDX.  Runs state = state*31 + (uint64_t)x for
 * n = (x & 7) + 1 iterations starting from state = y, then returns the
 * low 32 bits.
 * Lift target: vm_mixed_args_loop_target.
 *
 * Distinct from vm_two_input_loop (both i32) and vm_i64_return_loop
 * (single i64 in/out): here the lifter must consume RCX as a 32-bit value
 * (with sign extension to i64 for the additive term) and RDX as a full
 * 64-bit value live across the loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum MaVmPc {
    MA_LOAD       = 0,
    MA_INIT       = 1,
    MA_LOOP_CHECK = 2,
    MA_LOOP_BODY  = 3,
    MA_LOOP_INC   = 4,
    MA_HALT       = 5,
};

__declspec(noinline)
unsigned int vm_mixed_args_loop_target(int x, uint64_t y) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int64_t  add   = 0;
    int      pc    = MA_LOAD;

    while (1) {
        if (pc == MA_LOAD) {
            n     = (x & 7) + 1;
            state = y;
            add   = (int64_t)x;        /* sign-extend i32 -> i64 */
            pc = MA_INIT;
        } else if (pc == MA_INIT) {
            idx = 0;
            pc = MA_LOOP_CHECK;
        } else if (pc == MA_LOOP_CHECK) {
            pc = (idx < n) ? MA_LOOP_BODY : MA_HALT;
        } else if (pc == MA_LOOP_BODY) {
            state = state * 31ull + (uint64_t)add;
            pc = MA_LOOP_INC;
        } else if (pc == MA_LOOP_INC) {
            idx = idx + 1;
            pc = MA_LOOP_CHECK;
        } else if (pc == MA_HALT) {
            return (unsigned int)(state & 0xFFFFFFFFu);
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_mixed_args(1,0xCAFEBABE)=%u vm_mixed_args(0xFF,0x123456789ABCDEF0)=%u\n",
           vm_mixed_args_loop_target(1, 0xCAFEBABEull),
           vm_mixed_args_loop_target(0xFF, 0x123456789ABCDEF0ull));
    return 0;
}
