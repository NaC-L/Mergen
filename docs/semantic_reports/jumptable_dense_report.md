# jumptable_dense - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/jumptable_dense.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_dense.ll`
- **Symbol:** `jumptable_dense_target`
- **Native driver:** `rewrite-regression-work/eq/jumptable_dense_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jumptable_dense_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 100 | 100 | 100 | yes | case 0 |
| 2 | RCX=1 | 200 | 200 | 200 | yes | case 1 |
| 3 | RCX=2 | 300 | 300 | 300 | yes | case 2 |
| 4 | RCX=3 | 400 | 400 | 400 | yes | case 3 |
| 5 | RCX=4 | 500 | 500 | 500 | yes | case 4 |
| 6 | RCX=5 | 600 | 600 | 600 | yes | case 5 |
| 7 | RCX=6 | 700 | 700 | 700 | yes | case 6 |
| 8 | RCX=7 | 800 | 800 | 800 | yes | case 7 |
| 9 | RCX=8 | 0 | 0 | 0 | yes | default (>7) |
| 10 | RCX=100 | 0 | 0 | 0 | yes | default far |

## Source

```nasm
default rel
bits 64

global start
global jumptable_dense_target
extern ExitProcess

section .text
; 8-way dense jump table on symbolic ECX input.
; ecx 0->100, 1->200, 2->300, 3->400, 4->500, 5->600, 6->700, 7->800, else->0
jumptable_dense_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 7
    ja jt_d_default
    lea rcx, [jt_dense]
    jmp [rcx + rax*8]

jt_d_case0:
    mov eax, 100
    jmp jt_d_done
jt_d_case1:
    mov eax, 200
    jmp jt_d_done
jt_d_case2:
    mov eax, 300
    jmp jt_d_done
jt_d_case3:
    mov eax, 400
    jmp jt_d_done
jt_d_case4:
    mov eax, 500
    jmp jt_d_done
jt_d_case5:
    mov eax, 600
    jmp jt_d_done
jt_d_case6:
    mov eax, 700
    jmp jt_d_done
jt_d_case7:
    mov eax, 800
    jmp jt_d_done
jt_d_default:
    mov eax, 0
jt_d_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 5
    call jumptable_dense_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
; Dense jump table: 8 entries (cases 0-7)
jt_dense:
    dq jt_d_case0
    dq jt_d_case1
    dq jt_d_case2
    dq jt_d_case3
    dq jt_d_case4
    dq jt_d_case5
    dq jt_d_case6
    dq jt_d_case7
```
