# diamond - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/diamond.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/diamond.ll`
- **Symbol:** `diamond_target`
- **IR size:** 18 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=7 | 51 | 51 | pass | odd: (7+10)*3 |
| 2 | RCX=1 | 33 | 33 | pass | odd: (1+10)*3 |
| 3 | RCX=3 | 39 | 39 | pass | odd: (3+10)*3 |
| 4 | RCX=11 | 63 | 63 | pass | odd: (11+10)*3 |
| 5 | RCX=6 | 3 | 3 | pass | even: (6-5)*3 |
| 6 | RCX=8 | 9 | 9 | pass | even: (8-5)*3 |
| 7 | RCX=10 | 15 | 15 | pass | even: (10-5)*3 |
| 8 | RCX=100 | 285 | 285 | pass | even: (100-5)*3 |

## Source

```nasm
default rel
bits 64

global start
global diamond_target
extern ExitProcess

section .text
; Diamond-shaped CFG: two paths merge then continue.
;   if ecx is odd: eax = ecx + 10
;   else:          eax = ecx - 5
;   then:          eax *= 3
; Symbolic input → expect select/phi at merge, then mul by 3.
diamond_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    test eax, 1
    jz .even
    add eax, 10
    jmp .merge
.even:
    sub eax, 5
.merge:
    imul eax, eax, 3
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 7
    call diamond_target
    mov ecx, eax
    call ExitProcess
```
