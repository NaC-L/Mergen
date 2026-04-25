# nested_branch - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/nested_branch.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/nested_branch.ll`
- **Symbol:** `nested_branch_target`
- **Native driver:** `rewrite-regression-work/eq/nested_branch_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `nested_branch_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 100 | 100 | 100 | yes | <=10 |
| 2 | RCX=5 | 100 | 100 | 100 | yes | <=10 interior |
| 3 | RCX=10 | 100 | 100 | 100 | yes | <=10 boundary |
| 4 | RCX=11 | 200 | 200 | 200 | yes | 11..20 |
| 5 | RCX=15 | 200 | 200 | 200 | yes | 11..20 interior |
| 6 | RCX=20 | 200 | 200 | 200 | yes | <=20 boundary |
| 7 | RCX=21 | 300 | 300 | 300 | yes | >20 |
| 8 | RCX=100 | 300 | 300 | 300 | yes | >20 far |

## Source

```nasm
default rel
bits 64

global start
global nested_branch_target
extern ExitProcess

section .text
; 3-way nested if/else on symbolic RCX input.
; if ecx <= 10 → 100
; else if ecx <= 20 → 200
; else → 300
; All comparisons survive as symbolic selects/phis in IR.
nested_branch_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 10
    jg .above10
    mov eax, 100
    jmp .done
.above10:
    cmp eax, 20
    jg .above20
    mov eax, 200
    jmp .done
.above20:
    mov eax, 300
.done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 15
    call nested_branch_target
    mov ecx, eax
    call ExitProcess
```
