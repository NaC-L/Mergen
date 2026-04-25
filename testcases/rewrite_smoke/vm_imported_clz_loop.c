/* PC-state VM whose body calls __builtin_clz (lowered by clang to
 * @llvm.ctlz.i32) on different transforms of x.
 * Lift target: vm_imported_clz_loop_target.
 * Goal: cover a third recognized-intrinsic shape (after abs and popcount).
 * The argument is OR'd with 1 to keep clz well-defined.
 */
#include <stdio.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_CHECK      = 2,
    CZ_BODY_XOR   = 3,
    CZ_BODY_OR    = 4,
    CZ_BODY_CALL  = 5,
    CZ_BODY_ADD   = 6,
    CZ_BODY_INC   = 7,
    CZ_HALT       = 8,
};

__declspec(noinline)
int vm_imported_clz_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int v     = 0;
    int cnt   = 0;
    int pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = CZ_INIT;
        } else if (pc == CZ_INIT) {
            idx = 0;
            pc = CZ_CHECK;
        } else if (pc == CZ_CHECK) {
            pc = (idx < limit) ? CZ_BODY_XOR : CZ_HALT;
        } else if (pc == CZ_BODY_XOR) {
            v = x ^ (idx * 0x37);
            pc = CZ_BODY_OR;
        } else if (pc == CZ_BODY_OR) {
            v = v | 1;
            pc = CZ_BODY_CALL;
        } else if (pc == CZ_BODY_CALL) {
            cnt = __builtin_clz((unsigned)v);
            pc = CZ_BODY_ADD;
        } else if (pc == CZ_BODY_ADD) {
            sum = sum + cnt;
            pc = CZ_BODY_INC;
        } else if (pc == CZ_BODY_INC) {
            idx = idx + 1;
            pc = CZ_CHECK;
        } else if (pc == CZ_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_clz_loop(0xFF)=%d vm_imported_clz_loop(0xCAFEBABE)=%d\n",
           vm_imported_clz_loop_target(0xFF),
           vm_imported_clz_loop_target((int)0xCAFEBABEu));
    return 0;
}
