# cmov_chain - semantic equivalence

- **Verdict:** PASS
- **Cases:** 5/5 passed
- **Source:** `testcases/rewrite_smoke/cmov_chain.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/cmov_chain.ll`
- **Symbol:** `cmov_chain_target`
- **IR size:** 14 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 150 | 150 | pass | <=10: 100+50 |
| 2 | RCX=10 | 150 | 150 | pass | ==10: not >10 |
| 3 | RCX=11 | 250 | 250 | pass | >10: 200+50 |
| 4 | RCX=15 | 250 | 250 | pass | >10 interior |
| 5 | RCX=100 | 250 | 250 | pass | >10 far |

## Source

```nasm
default rel
bits 64

global start
global cmov_chain_target
extern ExitProcess

section .text
; Conditional moves (branchless select) on symbolic RCX:
;   eax = 100, edx = 200
;   if ecx > 10: eax = edx (200)
;   eax += 50
; Result is 150 or 250 depending on input.
; No branches in the CFG — cmov emits a select directly.
; Expect: select i1, add.
cmov_chain_target:
    push rbp
    mov rbp, rsp
    mov eax, 100
    mov edx, 200
    cmp ecx, 10
    cmovg eax, edx
    add eax, 50
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 15
    call cmov_chain_target
    mov ecx, eax
    call ExitProcess
```
