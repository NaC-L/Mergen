# jumptable_rel32 - semantic equivalence

- **Verdict:** PASS
- **Cases:** 7/7 passed
- **Source:** `testcases/rewrite_smoke/jumptable_rel32.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_rel32.ll`
- **Symbol:** `jumptable_rel32_target`
- **IR size:** 51 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 10 | 10 | pass | case 0 |
| 2 | RCX=1 | 20 | 20 | pass | case 1 |
| 3 | RCX=2 | 30 | 30 | pass | case 2 |
| 4 | RCX=3 | 40 | 40 | pass | case 3 |
| 5 | RCX=4 | 50 | 50 | pass | case 4 |
| 6 | RCX=5 | 999 | 999 | pass | default (>4) |
| 7 | RCX=100 | 999 | 999 | pass | default far |

## Source

```nasm
default rel
bits 64

global start
global jumptable_rel32_target
extern ExitProcess

section .text
; RIP-relative 32-bit offset jump table — the pattern MSVC /O2 actually
; generates for x64 switch statements.
;
; Pattern:
;   lea  rdx, [rip + jt_data]      ; table base
;   movsxd rax, dword [rdx + rcx*4]; signed 32-bit offset from table base
;   add  rax, rdx                   ; absolute target
;   jmp  rax                        ; indirect jump
;
; ecx 0->10, 1->20, 2->30, 3->40, 4->50, else->999
jumptable_rel32_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 4
    ja .default
    lea rdx, [.jt_data]
    movsxd rax, dword [rdx + rcx*4]
    add rax, rdx
    jmp rax

.case0:
    mov eax, 10
    jmp .done
.case1:
    mov eax, 20
    jmp .done
.case2:
    mov eax, 30
    jmp .done
.case3:
    mov eax, 40
    jmp .done
.case4:
    mov eax, 50
    jmp .done
.default:
    mov eax, 999
.done:
    pop rbp
    ret

; Table lives in .text so NASM can compute intra-section differences.
align 4
.jt_data:
    dd .case0 - .jt_data
    dd .case1 - .jt_data
    dd .case2 - .jt_data
    dd .case3 - .jt_data
    dd .case4 - .jt_data

start:
    sub rsp, 40
    mov ecx, 3
    call jumptable_rel32_target
    mov ecx, eax
    call ExitProcess
```
