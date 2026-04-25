/* PC-state VM with explicit return-PC stack: simulates CALL/RET semantics.
 * Lift target: vm_callret_loop_target.
 * Goal: cover a VM whose dispatch loop reaches the same handler block from
 * multiple call sites, and whose return PC is data on a tiny on-stack stack.
 * The "subroutine" is a counted multiply-accumulate that itself uses a loop;
 * main() invokes it twice with different symbolic arguments and sums the
 * results.  This shape is closer to real obfuscation VMs that thread
 * call/ret state through their dispatcher.
 *
 * Subroutine semantics: SUB(a) = a*a + a.
 * Implemented as a loop: tmp = 0; for i in 0..a-1: tmp += a; tmp += a.
 *   (i.e. tmp = a*a + a, computed via repeated addition so the loop is real.)
 */
#include <stdio.h>

enum CRVmPc {
    CR_INIT          = 0,
    CR_LOAD_ARG1     = 1,
    CR_CALL_SUB1     = 2,  /* push return = CR_AFTER_CALL1, jump to CR_SUB_ENTER */
    CR_AFTER_CALL1   = 3,
    CR_LOAD_ARG2     = 4,
    CR_CALL_SUB2     = 5,
    CR_AFTER_CALL2   = 6,
    CR_PACK_RESULT   = 7,
    CR_HALT          = 8,
    CR_SUB_ENTER     = 100,
    CR_SUB_INIT      = 101,
    CR_SUB_CHECK     = 102,
    CR_SUB_BODY_ADD  = 103,
    CR_SUB_BODY_INC  = 104,
    CR_SUB_TAIL_ADD  = 105,
    CR_SUB_RETURN    = 106,
};

__declspec(noinline)
int vm_callret_loop_target(int x) {
    int rstack[2];
    int rsp     = 0;
    int pc      = CR_INIT;
    int arg     = 0;
    int i       = 0;
    int tmp     = 0;
    int ret_val = 0;
    int r1      = 0;
    int r2      = 0;
    int result  = 0;

    while (1) {
        if (pc == CR_INIT) {
            pc = CR_LOAD_ARG1;
        } else if (pc == CR_LOAD_ARG1) {
            arg = x & 7;
            pc = CR_CALL_SUB1;
        } else if (pc == CR_CALL_SUB1) {
            rstack[rsp] = CR_AFTER_CALL1;
            rsp = rsp + 1;
            pc = CR_SUB_ENTER;
        } else if (pc == CR_AFTER_CALL1) {
            r1 = ret_val;
            pc = CR_LOAD_ARG2;
        } else if (pc == CR_LOAD_ARG2) {
            arg = (x >> 3) & 7;
            pc = CR_CALL_SUB2;
        } else if (pc == CR_CALL_SUB2) {
            rstack[rsp] = CR_AFTER_CALL2;
            rsp = rsp + 1;
            pc = CR_SUB_ENTER;
        } else if (pc == CR_AFTER_CALL2) {
            r2 = ret_val;
            pc = CR_PACK_RESULT;
        } else if (pc == CR_PACK_RESULT) {
            result = r1 + r2;
            pc = CR_HALT;
        } else if (pc == CR_HALT) {
            return result;
        } else if (pc == CR_SUB_ENTER) {
            pc = CR_SUB_INIT;
        } else if (pc == CR_SUB_INIT) {
            tmp = 0;
            i = 0;
            pc = CR_SUB_CHECK;
        } else if (pc == CR_SUB_CHECK) {
            pc = (i < arg) ? CR_SUB_BODY_ADD : CR_SUB_TAIL_ADD;
        } else if (pc == CR_SUB_BODY_ADD) {
            tmp = tmp + arg;
            pc = CR_SUB_BODY_INC;
        } else if (pc == CR_SUB_BODY_INC) {
            i = i + 1;
            pc = CR_SUB_CHECK;
        } else if (pc == CR_SUB_TAIL_ADD) {
            tmp = tmp + arg;
            pc = CR_SUB_RETURN;
        } else if (pc == CR_SUB_RETURN) {
            ret_val = tmp;
            rsp = rsp - 1;
            pc = rstack[rsp];
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_callret_loop(7)=%d vm_callret_loop(63)=%d\n",
           vm_callret_loop_target(7), vm_callret_loop_target(63));
    return 0;
}
