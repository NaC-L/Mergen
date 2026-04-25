# bytecode_vm_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 6/6 equivalent
- **Source:** `testcases/rewrite_smoke/bytecode_vm_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/bytecode_vm_loop.ll`
- **Symbol:** `bytecode_vm_loop_target`
- **Native driver:** `rewrite-regression-work/eq/bytecode_vm_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `bytecode_vm_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 40 | 40 | 40 | yes | even program returns constant handler |
| 2 | RCX=1 | 0 | 0 | 0 | yes | odd bytecode loop limit 1 returns 0 |
| 3 | RCX=3 | 3 | 3 | 3 | yes | odd bytecode loop: 0+1+2 |
| 4 | RCX=5 | 10 | 10 | 10 | yes | odd bytecode loop: 0+1+2+3+4 |
| 5 | RCX=7 | 21 | 21 | 21 | yes | odd bytecode loop: 0..6 |
| 6 | RCX=8 | 40 | 40 | 40 | yes | even program ignores odd loop body |

## Source

```c
/* Compiler-friendly VM with the loop implemented in VM program-counter state.
 * Lift target: bytecode_vm_loop_target.
 * Goal: keep the loop inside interpreter state instead of native source control
 * flow, while avoiding external bytecode loads and compiler jump tables.
 */
#include <stdio.h>

enum FriendlyVmPc {
    VM_EVEN_CONST = 0,
    VM_EVEN_HALT = 1,
    VM_ODD_LOAD_LIMIT = 10,
    VM_ODD_CLEAR_ACC = 11,
    VM_ODD_CLEAR_INDEX = 12,
    VM_ODD_CHECK = 13,
    VM_ODD_BODY = 14,
    VM_ODD_HALT = 15,
};

__declspec(noinline)
int bytecode_vm_loop_target(int x) {
    int pc = (x & 1) ? VM_ODD_LOAD_LIMIT : VM_EVEN_CONST;
    int acc = 0;
    int index = 0;
    int limit = 0;

    while (1) {
        if (pc == VM_EVEN_CONST) {
            acc = 40;
            pc = VM_EVEN_HALT;
        } else if (pc == VM_EVEN_HALT) {
            return acc;
        } else if (pc == VM_ODD_LOAD_LIMIT) {
            limit = x & 7;
            pc = VM_ODD_CLEAR_ACC;
        } else if (pc == VM_ODD_CLEAR_ACC) {
            acc = 0;
            pc = VM_ODD_CLEAR_INDEX;
        } else if (pc == VM_ODD_CLEAR_INDEX) {
            index = 0;
            pc = VM_ODD_CHECK;
        } else if (pc == VM_ODD_CHECK) {
            pc = (index < limit) ? VM_ODD_BODY : VM_ODD_HALT;
        } else if (pc == VM_ODD_BODY) {
            acc += index;
            index += 1;
            pc = VM_ODD_CHECK;
        } else if (pc == VM_ODD_HALT) {
            return acc;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("bytecode_vm_loop(5)=%d bytecode_vm_loop(8)=%d\n",
           bytecode_vm_loop_target(5), bytecode_vm_loop_target(8));
    return 0;
}
```
