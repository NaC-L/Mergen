# vm_fibonacci_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_fibonacci_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_fibonacci_loop.ll`
- **Symbol:** `vm_fibonacci_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_fibonacci_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_fibonacci_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | fib(0) |
| 2 | RCX=1 | 1 | 1 | 1 | yes | fib(1) |
| 3 | RCX=2 | 1 | 1 | 1 | yes | fib(2) |
| 4 | RCX=3 | 2 | 2 | 2 | yes | fib(3) |
| 5 | RCX=5 | 5 | 5 | 5 | yes | fib(5) |
| 6 | RCX=7 | 13 | 13 | 13 | yes | fib(7) |
| 7 | RCX=10 | 55 | 55 | 55 | yes | fib(10) |
| 8 | RCX=12 | 144 | 144 | 144 | yes | fib(12) |
| 9 | RCX=15 | 610 | 610 | 610 | yes | fib(15) |
| 10 | RCX=16 | 0 | 0 | 0 | yes | fib(0) again (mask drops bit 4) |

## Source

```c
/* PC-state VM computing Fibonacci numbers via a two-register recurrence.
 * Lift target: vm_fibonacci_loop_target.
 * Goal: exercise a loop whose body updates two interdependent state
 * variables (a, b = b, a+b).  Iteration count n = x & 15 is symbolic so
 * the result depends on the input.  Returns fib(n).
 */
#include <stdio.h>

enum FibVmPc {
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
int vm_fibonacci_loop_target(int x) {
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

int main(void) {
    printf("vm_fibonacci_loop(7)=%d vm_fibonacci_loop(12)=%d\n",
           vm_fibonacci_loop_target(7), vm_fibonacci_loop_target(12));
    return 0;
}
```
