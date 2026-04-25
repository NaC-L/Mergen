# switch_3way - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 6/6 equivalent
- **Source:** `testcases/rewrite_smoke/switch_3way.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/switch_3way.ll`
- **Symbol:** `switch_3way_target`
- **Native driver:** `rewrite-regression-work/eq/switch_3way_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `switch_3way_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=1 | 100 | 100 | 100 | yes | case 1 |
| 2 | RCX=2 | 200 | 200 | 200 | yes | case 2 |
| 3 | RCX=3 | 300 | 300 | 300 | yes | case 3 |
| 4 | RCX=0 | 999 | 999 | 999 | yes | default (0) |
| 5 | RCX=4 | 999 | 999 | 999 | yes | default (4) |
| 6 | RCX=100 | 999 | 999 | 999 | yes | default (100) |

## Source

```nasm
default rel
bits 64

global start
global switch_3way_target
extern ExitProcess

section .text
; 3-way computed jump on symbolic ECX input.
; if ecx == 1 → return 100
; if ecx == 2 → return 200
; if ecx == 3 → return 300
; else (default) → return 999
; Tests multi-target branch resolution (>2 targets).
switch_3way_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 1
    je .case1
    cmp eax, 2
    je .case2
    cmp eax, 3
    je .case3
    ; default
    mov eax, 999
    jmp .done
.case1:
    mov eax, 100
    jmp .done
.case2:
    mov eax, 200
    jmp .done
.case3:
    mov eax, 300
.done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 2
    call switch_3way_target
    mov ecx, eax
    call ExitProcess
```
