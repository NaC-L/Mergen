/* PC-state VM whose body calls _rotr (lowered by clang to @llvm.fshr.i32)
 * with both value and rotation count varying per iteration.
 * Lift target: vm_imported_rotr_loop_target.
 *
 * Mirrors the structure of vm_imported_rotl_loop, with `_rotr` instead
 * of `_rotl`. Funnel-shift right is a separate intrinsic shape (fshr)
 * and the existing rotl sample alone does not exercise it.
 *
 * The rotate amount is symbolic and depends on the loop index, so each
 * call has a distinct pre/post bit pattern and the lifter cannot
 * constant-fold the call away.
 */
#include <stdio.h>
#include <stdlib.h>

enum RrVmPc {
    RR_LOAD       = 0,
    RR_INIT       = 1,
    RR_CHECK      = 2,
    RR_BODY_XOR   = 3,
    RR_BODY_AMOUNT= 4,
    RR_BODY_CALL  = 5,
    RR_BODY_ADD   = 6,
    RR_BODY_INC   = 7,
    RR_HALT       = 8,
};

__declspec(noinline)
int vm_imported_rotr_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned amt   = 0;
    unsigned rot   = 0;
    int pc         = RR_LOAD;

    while (1) {
        if (pc == RR_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = RR_INIT;
        } else if (pc == RR_INIT) {
            idx = 0;
            pc = RR_CHECK;
        } else if (pc == RR_CHECK) {
            pc = (idx < limit) ? RR_BODY_XOR : RR_HALT;
        } else if (pc == RR_BODY_XOR) {
            v = (unsigned)x ^ (idx * 0x55);
            pc = RR_BODY_AMOUNT;
        } else if (pc == RR_BODY_AMOUNT) {
            amt = (idx + 3) & 31;
            pc = RR_BODY_CALL;
        } else if (pc == RR_BODY_CALL) {
            rot = _rotr(v, (int)amt);
            pc = RR_BODY_ADD;
        } else if (pc == RR_BODY_ADD) {
            sum = sum + rot;
            pc = RR_BODY_INC;
        } else if (pc == RR_BODY_INC) {
            idx = idx + 1;
            pc = RR_CHECK;
        } else if (pc == RR_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_rotr_loop(0xCAFE)=%u vm_imported_rotr_loop(0xDEADBEEF)=%u\n",
           (unsigned)vm_imported_rotr_loop_target(0xCAFE),
           (unsigned)vm_imported_rotr_loop_target((int)0xDEADBEEFu));
    return 0;
}
