# switch_3way - semantic equivalence

- **Verdict:** PASS
- **Cases:** 6/6 passed
- **Source:** `testcases/rewrite_smoke/switch_3way.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/switch_3way.ll`
- **Symbol:** `switch_3way_target`
- **IR size:** 29 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=1 | 100 | 100 | pass | case 1 |
| 2 | RCX=2 | 200 | 200 | pass | case 2 |
| 3 | RCX=3 | 300 | 300 | pass | case 3 |
| 4 | RCX=0 | 999 | 999 | pass | default (0) |
| 5 | RCX=4 | 999 | 999 | pass | default (4) |
| 6 | RCX=100 | 999 | 999 | pass | default (100) |

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
