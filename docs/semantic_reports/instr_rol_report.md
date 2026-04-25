# instr_rol - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 1/1 equivalent
- **Source:** `testcases/rewrite_smoke/instr_rol.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/instr_rol.ll`
- **Symbol:** `instr_rol_target`
- **Native driver:** `rewrite-regression-work/eq/instr_rol_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `instr_rol_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | _(none)_ | 34 | 34 | 34 | yes | constant: rol(0x11,1)=0x22=34 |

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
