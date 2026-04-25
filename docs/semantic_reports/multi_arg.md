# multi_arg - semantic equivalence

- **Verdict:** PASS
- **Cases:** 5/5 passed
- **Source:** `testcases/rewrite_smoke/multi_arg.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/multi_arg.ll`
- **Symbol:** `multi_arg_target`
- **IR size:** 16 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=5, RDX=3 | 56 | 56 | pass | (5+3)*7 |
| 2 | RCX=0, RDX=0 | 0 | 0 | pass | (0+0)*7 |
| 3 | RCX=10, RDX=4 | 98 | 98 | pass | (10+4)*7 |
| 4 | RCX=1, RDX=1 | 14 | 14 | pass | (1+1)*7 |
| 5 | RCX=100, RDX=0 | 700 | 700 | pass | (100+0)*7 |

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
