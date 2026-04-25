/* PC-state VM whose loop body calls the imported `abs()` from msvcrt.
 * Lift target: vm_imported_abs_loop_target.
 * Goal: cover a VM dispatcher whose handler issues an indirect-thunk call
 * into a runtime DLL inside the loop, then accumulates the imported call's
 * return value into VM state.  This is the canonical real-obfuscation
 * shape: VM body wraps a real CRT call.
 */
#include <stdio.h>
#include <stdlib.h>

enum AbVmPc {
    AB_LOAD       = 0,
    AB_INIT       = 1,
    AB_CHECK      = 2,
    AB_BODY_DELTA = 3,
    AB_BODY_CALL  = 4,
    AB_BODY_ADD   = 5,
    AB_BODY_INC   = 6,
    AB_HALT       = 7,
};

__declspec(noinline)
int vm_imported_abs_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int delta = 0;
    int abs_result = 0;
    int threshold = 0;
    int pc    = AB_LOAD;

    while (1) {
        if (pc == AB_LOAD) {
            limit = (x & 7) + 1;
            threshold = (x >> 3) & 0xFF;
            sum = 0;
            pc = AB_INIT;
        } else if (pc == AB_INIT) {
            idx = 0;
            pc = AB_CHECK;
        } else if (pc == AB_CHECK) {
            pc = (idx < limit) ? AB_BODY_DELTA : AB_HALT;
        } else if (pc == AB_BODY_DELTA) {
            delta = (idx * 17) - threshold;
            pc = AB_BODY_CALL;
        } else if (pc == AB_BODY_CALL) {
            abs_result = abs(delta);
            pc = AB_BODY_ADD;
        } else if (pc == AB_BODY_ADD) {
            sum = sum + abs_result;
            pc = AB_BODY_INC;
        } else if (pc == AB_BODY_INC) {
            idx = idx + 1;
            pc = AB_CHECK;
        } else if (pc == AB_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_abs_loop(0x10)=%d vm_imported_abs_loop(0x40)=%d\n",
           vm_imported_abs_loop_target(0x10), vm_imported_abs_loop_target(0x40));
    return 0;
}
