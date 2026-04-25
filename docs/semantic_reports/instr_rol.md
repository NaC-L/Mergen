# instr_rol - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/instr_rol.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/instr_rol.ll`
- **Symbol:** `instr_rol_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 34 | 34 | pass | constant: rol(0x11,1)=0x22=34 |

## Source

```nasm
default rel
bits 64

global start
global instr_rol_target
extern ExitProcess

section .text
instr_rol_target:
    push rbp
    mov rbp, rsp
    mov eax, 0x11
    rol eax, 1
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_rol_target
    mov ecx, eax
    call ExitProcess
```
