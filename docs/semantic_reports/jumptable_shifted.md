# jumptable_shifted - semantic equivalence

- **Verdict:** PASS
- **Cases:** 9/9 passed
- **Source:** `testcases/rewrite_smoke/jumptable_shifted.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_shifted.ll`
- **Symbol:** `jumptable_shifted_target`
- **IR size:** 54 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=10 | 100 | 100 | pass | case 10 |
| 2 | RCX=11 | 200 | 200 | pass | case 11 |
| 3 | RCX=12 | 300 | 300 | pass | case 12 |
| 4 | RCX=13 | 400 | 400 | pass | case 13 |
| 5 | RCX=14 | 500 | 500 | pass | case 14 |
| 6 | RCX=9 | 0 | 0 | pass | default (below range) |
| 7 | RCX=15 | 0 | 0 | pass | default (above range) |
| 8 | RCX=0 | 0 | 0 | pass | default (zero) |
| 9 | RCX=100 | 0 | 0 | pass | default far |

## Source

```nasm
default rel
bits 64

global start
global jumptable_shifted_target
extern ExitProcess

section .text
; Base-shifted jump table: case values 10-14 (not starting at 0).
; Compiler subtracts the base before indexing: sub ecx, 10; cmp ecx, 4.
;
; ecx 10->100, 11->200, 12->300, 13->400, 14->500, else->0
jumptable_shifted_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    sub eax, 10             ; shift: cases 10-14 become indices 0-4
    cmp eax, 4
    ja jts_default           ; unsigned: also catches negative (underflow)
    lea rcx, [jts_table]
    jmp [rcx + rax*8]        ; absolute qword table

jts_case10:
    mov eax, 100
    jmp jts_done
jts_case11:
    mov eax, 200
    jmp jts_done
jts_case12:
    mov eax, 300
    jmp jts_done
jts_case13:
    mov eax, 400
    jmp jts_done
jts_case14:
    mov eax, 500
    jmp jts_done
jts_default:
    xor eax, eax
jts_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 12
    call jumptable_shifted_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
jts_table:
    dq jts_case10
    dq jts_case11
    dq jts_case12
    dq jts_case13
    dq jts_case14
```
