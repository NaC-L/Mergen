# bitchain - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/bitchain.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/bitchain.ll`
- **Symbol:** `bitchain_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 4090 | 4090 | pass | constant: 0x0FFA |

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
