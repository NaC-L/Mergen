# vm_outlined_wrapper_loop - semantic equivalence

- **Verdict:** N/A (no semantic cases declared)
- **Cases:** 0/0 passed
- **Source:** `testcases/rewrite_smoke/vm_outlined_wrapper_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_outlined_wrapper_loop.ll`
- **Symbol:** `vm_outlined_wrapper_loop_target`
- **IR size:** 18 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|

## Source

```c
/* Wrapper-based VM lift test: the lift target is `idk` (renamed
 * vm_outlined_wrapper_loop_target), which calls a __declspec(noinline)
 * inner VM target.  Documents how the lifter currently treats the
 * inner-call site (per build_iced/vm_fibonacci_loop_report.md it is
 * outlined as call inttoptr(...)).
 *
 * Lift target: vm_outlined_wrapper_loop_target.
 *
 * Goal: exercise a real-world Mergen scenario where the entry function is
 * a thin wrapper around the actual VM dispatcher.  Both pieces are present
 * in the same .exe so the lifter has the whole story; the test asks only
 * that the *wrapper* lifts cleanly, with the VM body intact when reached
 * by inlining or as a separately-resolvable call.
 */
#include <stdio.h>

enum FbVmPc {
    FB_INIT       = 0,
    FB_LOAD_N     = 1,
    FB_INIT_REGS  = 2,
    FB_CHECK      = 3,
    FB_BODY_TMP   = 4,
    FB_BODY_SHIFT = 5,
    FB_BODY_DEC   = 6,
    FB_HALT       = 7,
};

__declspec(noinline)
static int vm_fib_inner(int x) {
    int n   = 0;
    int a   = 0;
    int b   = 0;
    int tmp = 0;
    int pc  = FB_INIT;

    while (1) {
        if (pc == FB_INIT) {
            pc = FB_LOAD_N;
        } else if (pc == FB_LOAD_N) {
            n = x & 15;
            pc = FB_INIT_REGS;
        } else if (pc == FB_INIT_REGS) {
            a = 0;
            b = 1;
            pc = FB_CHECK;
        } else if (pc == FB_CHECK) {
            pc = (n > 0) ? FB_BODY_TMP : FB_HALT;
        } else if (pc == FB_BODY_TMP) {
            tmp = a + b;
            pc = FB_BODY_SHIFT;
        } else if (pc == FB_BODY_SHIFT) {
            a = b;
            b = tmp;
            pc = FB_BODY_DEC;
        } else if (pc == FB_BODY_DEC) {
            n = n - 1;
            pc = FB_CHECK;
        } else if (pc == FB_HALT) {
            return a;
        } else {
            return -1;
        }
    }
}

__declspec(noinline)
int vm_outlined_wrapper_loop_target(int x) {
    /* Wrapper that calls the noinline VM body twice with related inputs and
     * folds the results. The lifter has to either inline vm_fib_inner or
     * leave a call site that lli can resolve. */
    int a = vm_fib_inner(x);
    int b = vm_fib_inner(x + 1);
    return a + b;
}

int main(void) {
    printf("vm_outlined_wrapper_loop(7)=%d vm_outlined_wrapper_loop(12)=%d\n",
           vm_outlined_wrapper_loop_target(7),
           vm_outlined_wrapper_loop_target(12));
    return 0;
}
```
