# dummy_vm_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 6/6 equivalent
- **Source:** `testcases/rewrite_smoke/dummy_vm_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/dummy_vm_loop.ll`
- **Symbol:** `dummy_vm_loop_target`
- **Native driver:** `rewrite-regression-work/eq/dummy_vm_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `dummy_vm_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 40 | 40 | 40 | yes | even opcode takes constant handler |
| 2 | RCX=1 | 0 | 0 | 0 | yes | odd opcode loop with limit 1 returns 0 |
| 3 | RCX=3 | 3 | 3 | 3 | yes | odd opcode loop: 0+1+2 |
| 4 | RCX=5 | 10 | 10 | 10 | yes | odd opcode loop: 0+1+2+3+4 |
| 5 | RCX=7 | 21 | 21 | 21 | yes | odd opcode loop: 0..6 |
| 6 | RCX=8 | 40 | 40 | 40 | yes | even opcode ignores masked loop handler |

## Source

```c
/* Tiny dummy-VM-style state machine around a real local loop.
 * Lift target: dummy_vm_loop_target.
 * Goal: keep a VM-shaped dispatch shell while preserving a normal counted loop
 * inside one handler, so loop-generalization regressions cannot silently
 * collapse it into unresolved control flow.
 */
#include <stdio.h>

__declspec(noinline)
int dummy_vm_loop_target(int x) {
    int opcode = x & 1;
    int acc = 0;

    while (1) {
        switch (opcode) {
        case 0:
            acc = 40;
            opcode = 2;
            break;
        case 1: {
            int limit = x & 7;
            for (int i = 0; i < limit; i++)
                acc += i;
            opcode = 2;
            break;
        }
        case 2:
            return acc;
        default:
            return -1;
        }
    }
}

int main(void) {
    printf("dummy_vm_loop(5)=%d dummy_vm_loop(8)=%d\n",
           dummy_vm_loop_target(5), dummy_vm_loop_target(8));
    return 0;
}
```
