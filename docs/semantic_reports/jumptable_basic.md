# jumptable_basic - semantic equivalence

- **Verdict:** PASS
- **Cases:** 6/6 passed
- **Source:** `testcases/rewrite_smoke/jumptable_basic.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_basic.ll`
- **Symbol:** `jumptable_basic_target`
- **IR size:** 46 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 10 | 10 | pass | case 0 |
| 2 | RCX=1 | 20 | 20 | pass | case 1 |
| 3 | RCX=2 | 30 | 30 | pass | case 2 |
| 4 | RCX=3 | 40 | 40 | pass | case 3 |
| 5 | RCX=4 | 999 | 999 | pass | default (>3) |
| 6 | RCX=100 | 999 | 999 | pass | default far |

## Source

```nasm
default rel
bits 64

global start
global jumptable_basic_target
extern ExitProcess

section .text
; Real indirect jump table on symbolic ECX input.
; ecx 0 -> 10, 1 -> 20, 2 -> 30, 3 -> 40, else -> 999
; The jump is: jmp [jt_basic + rax*8]
; This is the pattern MSVC generates with /O2 for dense switches.
jumptable_basic_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx       ; eax = symbolic input
    cmp eax, 3
    ja jt_b_default     ; unsigned compare: if >3, default
    lea rcx, [jt_basic] ; base of jump table
    jmp [rcx + rax*8]   ; indirect jump through table

jt_b_case0:
    mov eax, 10
    jmp jt_b_done
jt_b_case1:
    mov eax, 20
    jmp jt_b_done
jt_b_case2:
    mov eax, 30
    jmp jt_b_done
jt_b_case3:
    mov eax, 40
    jmp jt_b_done
jt_b_default:
    mov eax, 999
jt_b_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 2
    call jumptable_basic_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
; Jump table: 4 entries (cases 0-3), absolute 64-bit pointers.
jt_basic:
    dq jt_b_case0
    dq jt_b_case1
    dq jt_b_case2
    dq jt_b_case3
```
