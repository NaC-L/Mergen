# instr_xor - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/instr_xor.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/instr_xor.ll`
- **Symbol:** `instr_xor_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 90 | 90 | pass | constant: 0x55^0x0F=0x5A=90 |

## Source

```nasm
default rel
bits 64

global start
global instr_xor_target
extern ExitProcess

section .text
instr_xor_target:
    push rbp
    mov rbp, rsp
    mov eax, 0x55
    xor eax, 0x0f
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_xor_target
    mov ecx, eax
    call ExitProcess
```
