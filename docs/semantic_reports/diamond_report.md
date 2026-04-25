# diamond - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/diamond.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/diamond.ll`
- **Symbol:** `diamond_target`
- **Native driver:** `rewrite-regression-work/eq/diamond_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `diamond_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=7 | 51 | 51 | 51 | yes | odd: (7+10)*3 |
| 2 | RCX=1 | 33 | 33 | 33 | yes | odd: (1+10)*3 |
| 3 | RCX=3 | 39 | 39 | 39 | yes | odd: (3+10)*3 |
| 4 | RCX=11 | 63 | 63 | 63 | yes | odd: (11+10)*3 |
| 5 | RCX=6 | 3 | 3 | 3 | yes | even: (6-5)*3 |
| 6 | RCX=8 | 9 | 9 | 9 | yes | even: (8-5)*3 |
| 7 | RCX=10 | 15 | 15 | 15 | yes | even: (10-5)*3 |
| 8 | RCX=100 | 285 | 285 | 285 | yes | even: (100-5)*3 |

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
