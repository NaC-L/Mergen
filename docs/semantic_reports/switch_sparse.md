# switch_sparse - semantic equivalence

- **Verdict:** PASS
- **Cases:** 7/7 passed
- **Source:** `testcases/rewrite_smoke/switch_sparse.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/switch_sparse.ll`
- **Symbol:** `switch_sparse_target`
- **IR size:** 33 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=10 | 11 | 11 | pass | case 10 |
| 2 | RCX=50 | 55 | 55 | pass | case 50 |
| 3 | RCX=200 | 222 | 222 | pass | case 200 |
| 4 | RCX=1000 | 1337 | 1337 | pass | case 1000 |
| 5 | RCX=0 | 4294967295 | 4294967295 | pass | default: 0xFFFFFFFF |
| 6 | RCX=100 | 4294967295 | 4294967295 | pass | default |
| 7 | RCX=500 | 4294967295 | 4294967295 | pass | default |

## Source

```nasm
default rel
bits 64

global start
global switch_sparse_target
extern ExitProcess

section .text
; Sparse switch on symbolic ECX input.
; Case values are NOT consecutive: 10, 50, 200, 1000.
; Tests multi-target branch resolution with large gaps between cases.
switch_sparse_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 10
    je .case10
    cmp eax, 50
    je .case50
    cmp eax, 200
    je .case200
    cmp eax, 1000
    je .case1000
    ; default
    mov eax, -1
    jmp .done
.case10:
    mov eax, 11
    jmp .done
.case50:
    mov eax, 55
    jmp .done
.case200:
    mov eax, 222
    jmp .done
.case1000:
    mov eax, 1337
.done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 200
    call switch_sparse_target
    mov ecx, eax
    call ExitProcess
```
