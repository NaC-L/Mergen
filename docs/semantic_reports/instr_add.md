# instr_add - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/instr_add.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/instr_add.ll`
- **Symbol:** `instr_add_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 12 | 12 | pass | constant: 7+5 |

## Source

```nasm
default rel
bits 64

global start
global instr_add_target
extern ExitProcess

section .text
instr_add_target:
    push rbp
    mov rbp, rsp
    mov eax, 7
    add eax, 5
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_add_target
    mov ecx, eax
    call ExitProcess
```
