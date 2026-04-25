# nested_branch - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/nested_branch.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/nested_branch.ll`
- **Symbol:** `nested_branch_target`
- **IR size:** 16 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 100 | 100 | pass | <=10 |
| 2 | RCX=5 | 100 | 100 | pass | <=10 interior |
| 3 | RCX=10 | 100 | 100 | pass | <=10 boundary |
| 4 | RCX=11 | 200 | 200 | pass | 11..20 |
| 5 | RCX=15 | 200 | 200 | pass | 11..20 interior |
| 6 | RCX=20 | 200 | 200 | pass | <=20 boundary |
| 7 | RCX=21 | 300 | 300 | pass | >20 |
| 8 | RCX=100 | 300 | 300 | pass | >20 far |

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
