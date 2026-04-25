# loop_simple - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/loop_simple.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/loop_simple.ll`
- **Symbol:** `loop_simple_target`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 6 | 6 | pass | constant: 3+2+1 |

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
