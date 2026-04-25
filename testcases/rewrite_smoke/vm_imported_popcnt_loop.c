/* PC-state VM whose body calls __builtin_popcount (lowered by clang to
 * @llvm.ctpop.i32) on different transforms of x.
 * Lift target: vm_imported_popcnt_loop_target.
 * Goal: cover a SECOND imported-intrinsic shape distinct from abs() to
 * confirm the lifter handles other recognized CRT/builtin lowerings inside
 * VM dispatchers.  Each iteration XORs x with a different constant and
 * sums the popcounts.
 */
#include <stdio.h>

enum PcVmPc {
    PC_LOAD       = 0,
    PC_INIT       = 1,
    PC_CHECK      = 2,
    PC_BODY_XOR   = 3,
    PC_BODY_CALL  = 4,
    PC_BODY_ADD   = 5,
    PC_BODY_INC   = 6,
    PC_HALT       = 7,
};

__declspec(noinline)
int vm_imported_popcnt_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int v     = 0;
    int cnt   = 0;
    int pc    = PC_LOAD;

    while (1) {
        if (pc == PC_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = PC_INIT;
        } else if (pc == PC_INIT) {
            idx = 0;
            pc = PC_CHECK;
        } else if (pc == PC_CHECK) {
            pc = (idx < limit) ? PC_BODY_XOR : PC_HALT;
        } else if (pc == PC_BODY_XOR) {
            v = x ^ (idx * 0x42);
            pc = PC_BODY_CALL;
        } else if (pc == PC_BODY_CALL) {
            cnt = __builtin_popcount((unsigned)v);
            pc = PC_BODY_ADD;
        } else if (pc == PC_BODY_ADD) {
            sum = sum + cnt;
            pc = PC_BODY_INC;
        } else if (pc == PC_BODY_INC) {
            idx = idx + 1;
            pc = PC_CHECK;
        } else if (pc == PC_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_popcnt_loop(0xFF)=%d vm_imported_popcnt_loop(0xCAFEBABE)=%d\n",
           vm_imported_popcnt_loop_target(0xFF),
           vm_imported_popcnt_loop_target((int)0xCAFEBABEu));
    return 0;
}
