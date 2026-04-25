# switch_sparse - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 7/7 equivalent
- **Source:** `testcases/rewrite_smoke/switch_sparse.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/switch_sparse.ll`
- **Symbol:** `switch_sparse_target`
- **Native driver:** `rewrite-regression-work/eq/switch_sparse_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `switch_sparse_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=10 | 11 | 11 | 11 | yes | case 10 |
| 2 | RCX=50 | 55 | 55 | 55 | yes | case 50 |
| 3 | RCX=200 | 222 | 222 | 222 | yes | case 200 |
| 4 | RCX=1000 | 1337 | 1337 | 1337 | yes | case 1000 |
| 5 | RCX=0 | 4294967295 | 4294967295 | 4294967295 | yes | default: 0xFFFFFFFF |
| 6 | RCX=100 | 4294967295 | 4294967295 | 4294967295 | yes | default |
| 7 | RCX=500 | 4294967295 | 4294967295 | 4294967295 | yes | default |

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
