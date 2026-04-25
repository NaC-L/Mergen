# indirect - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 1/1 equivalent
- **Source:** `testcases/rewrite_smoke/indirect.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/indirect.ll`
- **Symbol:** `jump_target`
- **Native driver:** `rewrite-regression-work/eq/indirect_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jump_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | _(none)_ | 53 | 53 | 53 | yes | constant: hardcoded case2 0x30+5 |

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
