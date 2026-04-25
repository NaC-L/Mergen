# loop_simple - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 1/1 equivalent
- **Source:** `testcases/rewrite_smoke/loop_simple.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/loop_simple.ll`
- **Symbol:** `loop_simple_target`
- **Native driver:** `rewrite-regression-work/eq/loop_simple_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `loop_simple_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | _(none)_ | 6 | 6 | 6 | yes | constant: 3+2+1 |

## Source

```nasm
default rel
bits 64

global start
global loop_simple_target
extern ExitProcess

section .text
; Tiny constant-bound countdown loop: sum = 3 + 2 + 1 = 6.
; ecx is overwritten with constant 3 immediately, so the
; concolic engine should unroll all 3 iterations and LLVM
; should constant-fold the result to 6.
loop_simple_target:
    push rbp
    mov rbp, rsp
    xor eax, eax
    mov ecx, 3
.loop:
    add eax, ecx
    dec ecx
    jnz .loop
    pop rbp
    ret

start:
    sub rsp, 40
    call loop_simple_target
    mov ecx, eax
    call ExitProcess
```
