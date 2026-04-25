# cmov_chain - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 5/5 equivalent
- **Source:** `testcases/rewrite_smoke/cmov_chain.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/cmov_chain.ll`
- **Symbol:** `cmov_chain_target`
- **Native driver:** `rewrite-regression-work/eq/cmov_chain_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `cmov_chain_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 150 | 150 | 150 | yes | <=10: 100+50 |
| 2 | RCX=10 | 150 | 150 | 150 | yes | ==10: not >10 |
| 3 | RCX=11 | 250 | 250 | 250 | yes | >10: 200+50 |
| 4 | RCX=15 | 250 | 250 | 250 | yes | >10 interior |
| 5 | RCX=100 | 250 | 250 | 250 | yes | >10 far |

## Source

```nasm
default rel
bits 64

global start
global cmov_chain_target
extern ExitProcess

section .text
; Conditional moves (branchless select) on symbolic RCX:
;   eax = 100, edx = 200
;   if ecx > 10: eax = edx (200)
;   eax += 50
; Result is 150 or 250 depending on input.
; No branches in the CFG — cmov emits a select directly.
; Expect: select i1, add.
cmov_chain_target:
    push rbp
    mov rbp, rsp
    mov eax, 100
    mov edx, 200
    cmp ecx, 10
    cmovg eax, edx
    add eax, 50
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 15
    call cmov_chain_target
    mov ecx, eax
    call ExitProcess
```
