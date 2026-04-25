# multi_arg - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 5/5 equivalent
- **Source:** `testcases/rewrite_smoke/multi_arg.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/multi_arg.ll`
- **Symbol:** `multi_arg_target`
- **Native driver:** `rewrite-regression-work/eq/multi_arg_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `multi_arg_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=5, RDX=3 | 56 | 56 | 56 | yes | (5+3)*7 |
| 2 | RCX=0, RDX=0 | 0 | 0 | 0 | yes | (0+0)*7 |
| 3 | RCX=10, RDX=4 | 98 | 98 | 98 | yes | (10+4)*7 |
| 4 | RCX=1, RDX=1 | 14 | 14 | 14 | yes | (1+1)*7 |
| 5 | RCX=100, RDX=0 | 700 | 700 | 700 | yes | (100+0)*7 |

## Source

```nasm
default rel
bits 64

global start
global multi_arg_target
extern ExitProcess

section .text
; Two symbolic arguments (RCX, RDX) combined:
;   result = (ecx + edx) * 7
; Since both inputs are symbolic, the IR cannot constant-fold.
; Expect to see add and mul operations in lifted IR.
multi_arg_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    add eax, edx
    imul eax, eax, 7
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 5
    mov edx, 3
    call multi_arg_target
    mov ecx, eax
    call ExitProcess
```
