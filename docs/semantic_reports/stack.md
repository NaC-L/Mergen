# stack - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/stack.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/stack.ll`
- **Symbol:** `stack_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 1717986918 | 1717986918 | pass | constant: 0x66666666 |

## Source

```nasm
default rel
bits 64

global start
global stack_target
extern ExitProcess

section .text
stack_target:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov dword [rsp + 16], 0x11111111
    mov eax, dword [rsp + 16]
    add eax, 0x22222222
    rol eax, 1
    add rsp, 32
    pop rbp
    ret

start:
    sub rsp, 40
    call stack_target
    mov ecx, eax
    call ExitProcess
```
