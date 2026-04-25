# branch - semantic equivalence

- **Verdict:** PASS
- **Cases:** 5/5 passed
- **Source:** `testcases/rewrite_smoke/branch.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/branch.ll`
- **Symbol:** `branch_target`
- **IR size:** 18 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 87 | 87 | pass | le path: (0+100)^0x33=87 |
| 2 | RCX=3 | 84 | 84 | pass | le path: (3+100)^0x33=84 |
| 3 | RCX=5 | 90 | 90 | pass | le boundary: (5+100)^0x33=90 |
| 4 | RCX=6 | 33 | 33 | pass | gt path: (6*3)^0x33=33 |
| 5 | RCX=10 | 45 | 45 | pass | gt path: (10*3)^0x33=45 |

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
