# indirect - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/indirect.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/indirect.ll`
- **Symbol:** `jump_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 53 | 53 | pass | constant: hardcoded case2 0x30+5 |

## Source

```nasm
default rel
bits 64

global start
global jump_target
extern ExitProcess

section .text
jump_target:
    push rbp
    mov rbp, rsp

    mov ecx, 2
    lea rax, [rel jump_table]
    movsxd rdx, dword [rax + rcx * 4]
    add rax, rdx
    jmp rax

case0:
    mov eax, 0x10
    jmp done_label
case1:
    mov eax, 0x20
    jmp done_label
case2:
    mov eax, 0x30
done_label:
    add eax, 5
    pop rbp
    ret

jump_table:
    dd case0 - jump_table
    dd case1 - jump_table
    dd case2 - jump_table

start:
    sub rsp, 40
    call jump_target
    mov ecx, eax
    call ExitProcess
```
