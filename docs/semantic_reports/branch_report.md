# branch - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 5/5 equivalent
- **Source:** `testcases/rewrite_smoke/branch.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/branch.ll`
- **Symbol:** `branch_target`
- **Native driver:** `rewrite-regression-work/eq/branch_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `branch_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 87 | 87 | 87 | yes | le path: (0+100)^0x33=87 |
| 2 | RCX=3 | 84 | 84 | 84 | yes | le path: (3+100)^0x33=84 |
| 3 | RCX=5 | 90 | 90 | 90 | yes | le boundary: (5+100)^0x33=90 |
| 4 | RCX=6 | 33 | 33 | 33 | yes | gt path: (6*3)^0x33=33 |
| 5 | RCX=10 | 45 | 45 | 45 | yes | gt path: (10*3)^0x33=45 |

## Source

```nasm
default rel
bits 64

global start
global branch_target
extern ExitProcess

section .text
branch_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 5
    jg .gt
    add eax, 100
    jmp .done
.gt:
    imul eax, eax, 3
.done:
    xor eax, 0x33
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 10
    call branch_target
    mov ecx, eax
    call ExitProcess
```
