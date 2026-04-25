# bitchain - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 1/1 equivalent
- **Source:** `testcases/rewrite_smoke/bitchain.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/bitchain.ll`
- **Symbol:** `bitchain_target`
- **Native driver:** `rewrite-regression-work/eq/bitchain_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `bitchain_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | _(none)_ | 4090 | 4090 | 4090 | yes | constant: 0x0FFA |

## Source

```nasm
default rel
bits 64

global start
global bitchain_target
extern ExitProcess

section .text
; Pure-constant bit manipulation chain. No symbolic inputs.
; eax = 0xFF
; shl eax, 8   → 0x0000FF00
; xor eax, 0xAA → 0x0000FFAA
; ror eax, 4   → 0xA0000FFA
; and eax, 0xFFFF → 0x0FFA = 4090
; LLVM must fold entire chain to ret i64 4090.
bitchain_target:
    push rbp
    mov rbp, rsp
    mov eax, 0xFF
    shl eax, 8
    xor eax, 0xAA
    ror eax, 4
    and eax, 0xFFFF
    pop rbp
    ret

start:
    sub rsp, 40
    call bitchain_target
    mov ecx, eax
    call ExitProcess
```
