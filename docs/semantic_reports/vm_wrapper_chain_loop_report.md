# vm_wrapper_chain_loop - original vs lifted equivalence

- **Verdict:** NA (no semantic cases declared)
- **Cases:** 0/0 equivalent
- **Source:** `testcases/rewrite_smoke/vm_wrapper_chain_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_wrapper_chain_loop.ll`
- **Symbol:** `vm_wrapper_chain_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_wrapper_chain_loop_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_wrapper_chain_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|

## Source

```c
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
```
