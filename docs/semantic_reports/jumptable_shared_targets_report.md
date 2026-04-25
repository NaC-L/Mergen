# jumptable_shared_targets - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/jumptable_shared_targets.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_shared_targets.ll`
- **Symbol:** `jumptable_shared_target`
- **Native driver:** `rewrite-regression-work/eq/jumptable_shared_targets_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jumptable_shared_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 10 | 10 | 10 | yes | case 0 (group a) |
| 2 | RCX=1 | 10 | 10 | 10 | yes | case 1 (group a shared) |
| 3 | RCX=2 | 20 | 20 | 20 | yes | case 2 (solo b) |
| 4 | RCX=3 | 30 | 30 | 30 | yes | case 3 (group c) |
| 5 | RCX=4 | 30 | 30 | 30 | yes | case 4 (group c shared) |
| 6 | RCX=5 | 40 | 40 | 40 | yes | case 5 (solo d) |
| 7 | RCX=6 | 999 | 999 | 999 | yes | default (>5) |
| 8 | RCX=100 | 999 | 999 | 999 | yes | default far |

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
