/* Two-level wrapper chain: outer -> middle -> inner VM body.  All three are
 * __declspec(noinline) so each is reachable as a distinct PE symbol.
 * Lift target: vm_wrapper_chain_loop_target (the OUTER).
 *
 * Goal: extend the outline-detection coverage from
 * vm_outlined_wrapper_loop (one wrapper level) to a multi-level call
 * chain.  The lifter needs to handle two intra-binary calls in a single
 * lift target.  Per build_iced/vm_fibonacci_loop_report.md the inner
 * function gets outlined as call inttoptr(addr) - this sample makes the
 * shape regressionable for two layers of that pattern.
 */
#include <stdio.h>

__declspec(noinline)
static int vm_inner_op(int v) {
    int n   = v & 7;
    int acc = 0;
    while (n > 0) {
        acc = acc + n;
        n = n - 1;
    }
    return acc;
}

__declspec(noinline)
static int vm_middle_op(int v) {
    return vm_inner_op(v) + vm_inner_op(v + 1);
}

__declspec(noinline)
int vm_wrapper_chain_loop_target(int x) {
    return vm_middle_op(x) + vm_middle_op(x + 2);
}

int main(void) {
    printf("vm_wrapper_chain_loop(7)=%d vm_wrapper_chain_loop(12)=%d\n",
           vm_wrapper_chain_loop_target(7),
           vm_wrapper_chain_loop_target(12));
    return 0;
}
