# instr_sub - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/instr_sub.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/instr_sub.ll`
- **Symbol:** `instr_sub_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 42 | 42 | pass | constant: 100-58 |

## Source

```nasm
default rel
bits 64

global start
global instr_sub_target
extern ExitProcess

section .text
instr_sub_target:
    push rbp
    mov rbp, rsp
    mov eax, 100
    sub eax, 58
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_sub_target
    mov ecx, eax
    call ExitProcess
```
