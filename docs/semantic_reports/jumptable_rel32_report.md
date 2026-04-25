# jumptable_rel32 - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 7/7 equivalent
- **Source:** `testcases/rewrite_smoke/jumptable_rel32.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_rel32.ll`
- **Symbol:** `jumptable_rel32_target`
- **Native driver:** `rewrite-regression-work/eq/jumptable_rel32_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jumptable_rel32_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 10 | 10 | 10 | yes | case 0 |
| 2 | RCX=1 | 20 | 20 | 20 | yes | case 1 |
| 3 | RCX=2 | 30 | 30 | 30 | yes | case 2 |
| 4 | RCX=3 | 40 | 40 | 40 | yes | case 3 |
| 5 | RCX=4 | 50 | 50 | 50 | yes | case 4 |
| 6 | RCX=5 | 999 | 999 | 999 | yes | default (>4) |
| 7 | RCX=100 | 999 | 999 | 999 | yes | default far |

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
