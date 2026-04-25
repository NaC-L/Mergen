/* PC-state VM whose body calls _rotl (lowered by clang to @llvm.fshl.i32)
 * with both value and rotation count varying per iteration.
 * Lift target: vm_imported_rotl_loop_target.
 * Goal: cover a sixth recognized-intrinsic shape - funnel-shift rotate.
 * The rotate amount is symbolic and depends on the loop index, so each
 * call has a distinct pre/post bit pattern.
 */
#include <stdio.h>
#include <stdlib.h>

enum RlVmPc {
    RL_LOAD       = 0,
    RL_INIT       = 1,
    RL_CHECK      = 2,
    RL_BODY_XOR   = 3,
    RL_BODY_AMOUNT= 4,
    RL_BODY_CALL  = 5,
    RL_BODY_ADD   = 6,
    RL_BODY_INC   = 7,
    RL_HALT       = 8,
};

__declspec(noinline)
int vm_imported_rotl_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned amt   = 0;
    unsigned rot   = 0;
    int pc         = RL_LOAD;

    while (1) {
        if (pc == RL_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = RL_INIT;
        } else if (pc == RL_INIT) {
            idx = 0;
            pc = RL_CHECK;
        } else if (pc == RL_CHECK) {
            pc = (idx < limit) ? RL_BODY_XOR : RL_HALT;
        } else if (pc == RL_BODY_XOR) {
            v = (unsigned)x ^ (idx * 0x55);
            pc = RL_BODY_AMOUNT;
        } else if (pc == RL_BODY_AMOUNT) {
            amt = (idx + 3) & 31;
            pc = RL_BODY_CALL;
        } else if (pc == RL_BODY_CALL) {
            rot = _rotl(v, (int)amt);
            pc = RL_BODY_ADD;
        } else if (pc == RL_BODY_ADD) {
            sum = sum + rot;
            pc = RL_BODY_INC;
        } else if (pc == RL_BODY_INC) {
            idx = idx + 1;
            pc = RL_CHECK;
        } else if (pc == RL_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_rotl_loop(0xCAFE)=%u vm_imported_rotl_loop(0xDEADBEEF)=%u\n",
           (unsigned)vm_imported_rotl_loop_target(0xCAFE),
           (unsigned)vm_imported_rotl_loop_target((int)0xDEADBEEFu));
    return 0;
}
