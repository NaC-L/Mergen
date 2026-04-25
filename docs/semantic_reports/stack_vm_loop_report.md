# stack_vm_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 6/6 equivalent
- **Source:** `testcases/rewrite_smoke/stack_vm_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/stack_vm_loop.ll`
- **Symbol:** `stack_vm_loop_target`
- **Native driver:** `rewrite-regression-work/eq/stack_vm_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `stack_vm_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 40 | 40 | 40 | yes | even program returns constant handler |
| 2 | RCX=1 | 0 | 0 | 0 | yes | odd stack loop limit 1 returns 0 |
| 3 | RCX=3 | 3 | 3 | 3 | yes | odd stack loop: 0+1+2 |
| 4 | RCX=5 | 10 | 10 | 10 | yes | odd stack loop: 0+1+2+3+4 |
| 5 | RCX=7 | 21 | 21 | 21 | yes | odd stack loop: 0..6 |
| 6 | RCX=8 | 40 | 40 | 40 | yes | even program ignores odd loop body |

## Source

```c
/* Harsher stack-based VM with explicit push/pop/add/sub/jnz-style states.
 * Lift target: stack_vm_loop_target.
 * Goal: keep the loop entirely in VM state while modeling a more realistic
 * stack interpreter than the compiler-friendly register/local VM.
 *
 * This version keeps the stack explicit but collapses bookkeeping-only microstates
 * and uses fixed 2-slot stack transitions so the sample remains lli-executable
 * without reintroducing the branchy per-slot dispatcher forest that hit budget 503.
 */
#include <stdio.h>

#define VM_PUSH0(VALUE)                                                          \
    do {                                                                        \
        s0 = (VALUE);                                                           \
        sp = 1;                                                                 \
    } while (0)

#define VM_PUSH1(VALUE)                                                          \
    do {                                                                        \
        s1 = (VALUE);                                                           \
        sp = 2;                                                                 \
    } while (0)

#define VM_POP1(OUT)                                                             \
    do {                                                                        \
        (OUT) = s1;                                                             \
        sp = 1;                                                                 \
    } while (0)

#define VM_POP0(OUT)                                                             \
    do {                                                                        \
        (OUT) = s0;                                                             \
        sp = 0;                                                                 \
    } while (0)

enum StackVmPc {
    VM_EVEN_PUSH_40 = 0,
    VM_EVEN_HALT = 1,

    VM_ODD_INIT_LIMIT = 10,
    VM_ODD_INIT_ACC = 11,
    VM_ODD_INIT_INDEX = 12,
    VM_ODD_SUB_JNZ = 13,
    VM_ODD_BODY_ACC = 14,
    VM_ODD_BODY_INDEX = 15,
    VM_ODD_HALT = 16,
};

__declspec(noinline)
int stack_vm_loop_target(int x) {
    int sp = 0;
    int s0 = 0;
    int s1 = 0;
    int acc = 0;
    int index = 0;
    int limit = 0;
    int pc = (x & 1) ? VM_ODD_INIT_LIMIT : VM_EVEN_PUSH_40;
    int lhs = 0;
    int rhs = 0;
    int cond = 0;

    while (1) {
        if (pc == VM_EVEN_PUSH_40) {
            VM_PUSH0(40);
            pc = VM_EVEN_HALT;
        } else if (pc == VM_EVEN_HALT) {
            VM_POP0(lhs);
            return lhs;
        } else if (pc == VM_ODD_INIT_LIMIT) {
            VM_PUSH0(x & 7);
            VM_POP0(limit);
            pc = VM_ODD_INIT_ACC;
        } else if (pc == VM_ODD_INIT_ACC) {
            VM_PUSH0(0);
            VM_POP0(acc);
            pc = VM_ODD_INIT_INDEX;
        } else if (pc == VM_ODD_INIT_INDEX) {
            VM_PUSH0(0);
            VM_POP0(index);
            pc = VM_ODD_SUB_JNZ;
        } else if (pc == VM_ODD_SUB_JNZ) {
            VM_PUSH0(limit);
            VM_PUSH1(index);
            VM_POP1(rhs);
            VM_POP0(lhs);
            VM_PUSH0(lhs - rhs);
            VM_POP0(cond);
            pc = (cond != 0) ? VM_ODD_BODY_ACC : VM_ODD_HALT;
        } else if (pc == VM_ODD_BODY_ACC) {
            VM_PUSH0(acc);
            VM_PUSH1(index);
            VM_POP1(rhs);
            VM_POP0(lhs);
            VM_PUSH0(lhs + rhs);
            VM_POP0(acc);
            pc = VM_ODD_BODY_INDEX;
        } else if (pc == VM_ODD_BODY_INDEX) {
            VM_PUSH0(index);
            VM_PUSH1(1);
            VM_POP1(rhs);
            VM_POP0(lhs);
            VM_PUSH0(lhs + rhs);
            VM_POP0(index);
            pc = VM_ODD_SUB_JNZ;
        } else if (pc == VM_ODD_HALT) {
            VM_PUSH0(acc);
            VM_POP0(lhs);
            return lhs;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("stack_vm_loop(5)=%d stack_vm_loop(8)=%d\n",
           stack_vm_loop_target(5), stack_vm_loop_target(8));
    return 0;
}
```
