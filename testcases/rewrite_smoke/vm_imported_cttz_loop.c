/* PC-state VM whose body calls __builtin_ctz (lowered to @llvm.cttz.i32) on
 * x XOR'd with a per-iteration constant.
 * Lift target: vm_imported_cttz_loop_target.
 * Goal: cover a fifth recognized-intrinsic shape.  cttz exercises the
 * trailing-zero count side of the bit-scan family (after vm_imported_clz_loop).
 * Argument is OR'd with a high bit to keep cttz well-defined.
 */
#include <stdio.h>

enum CtVmPc {
    CT_LOAD       = 0,
    CT_INIT       = 1,
    CT_CHECK      = 2,
    CT_BODY_XOR   = 3,
    CT_BODY_OR    = 4,
    CT_BODY_CALL  = 5,
    CT_BODY_ADD   = 6,
    CT_BODY_INC   = 7,
    CT_HALT       = 8,
};

__declspec(noinline)
int vm_imported_cttz_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int v     = 0;
    int cnt   = 0;
    int pc    = CT_LOAD;

    while (1) {
        if (pc == CT_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = CT_INIT;
        } else if (pc == CT_INIT) {
            idx = 0;
            pc = CT_CHECK;
        } else if (pc == CT_CHECK) {
            pc = (idx < limit) ? CT_BODY_XOR : CT_HALT;
        } else if (pc == CT_BODY_XOR) {
            v = x ^ (idx * 0x91);
            pc = CT_BODY_OR;
        } else if (pc == CT_BODY_OR) {
            v = v | 0x40000000;
            pc = CT_BODY_CALL;
        } else if (pc == CT_BODY_CALL) {
            cnt = __builtin_ctz((unsigned)v);
            pc = CT_BODY_ADD;
        } else if (pc == CT_BODY_ADD) {
            sum = sum + cnt;
            pc = CT_BODY_INC;
        } else if (pc == CT_BODY_INC) {
            idx = idx + 1;
            pc = CT_CHECK;
        } else if (pc == CT_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_cttz_loop(0xFF)=%d vm_imported_cttz_loop(0xCAFE)=%d\n",
           vm_imported_cttz_loop_target(0xFF),
           vm_imported_cttz_loop_target(0xCAFE));
    return 0;
}
