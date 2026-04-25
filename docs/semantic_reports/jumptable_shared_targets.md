# jumptable_shared_targets - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/jumptable_shared_targets.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_shared_targets.ll`
- **Symbol:** `jumptable_shared_target`
- **IR size:** 49 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 10 | 10 | pass | case 0 (group a) |
| 2 | RCX=1 | 10 | 10 | pass | case 1 (group a shared) |
| 3 | RCX=2 | 20 | 20 | pass | case 2 (solo b) |
| 4 | RCX=3 | 30 | 30 | pass | case 3 (group c) |
| 5 | RCX=4 | 30 | 30 | pass | case 4 (group c shared) |
| 6 | RCX=5 | 40 | 40 | pass | case 5 (solo d) |
| 7 | RCX=6 | 999 | 999 | pass | default (>5) |
| 8 | RCX=100 | 999 | 999 | pass | default far |

## Source

```nasm
default rel
bits 64

global start
global jumptable_shared_target
extern ExitProcess

section .text
; Jump table with shared case targets: multiple indices route to the
; same handler.  Tests that the lifter correctly merges equivalent
; table entries.
;
; ecx 0->10, 1->10, 2->20, 3->30, 4->30, 5->40, else->999
jumptable_shared_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 5
    ja jtsh_default
    lea rcx, [jtsh_table]
    jmp [rcx + rax*8]

jtsh_group_a:               ; cases 0, 1
    mov eax, 10
    jmp jtsh_done
jtsh_solo_b:                ; case 2
    mov eax, 20
    jmp jtsh_done
jtsh_group_c:               ; cases 3, 4
    mov eax, 30
    jmp jtsh_done
jtsh_solo_d:                ; case 5
    mov eax, 40
    jmp jtsh_done
jtsh_default:
    mov eax, 999
jtsh_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 4
    call jumptable_shared_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
jtsh_table:
    dq jtsh_group_a     ; case 0
    dq jtsh_group_a     ; case 1  (shared with 0)
    dq jtsh_solo_b      ; case 2
    dq jtsh_group_c     ; case 3
    dq jtsh_group_c     ; case 4  (shared with 3)
    dq jtsh_solo_d      ; case 5
```
