# jumptable_basic - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 6/6 equivalent
- **Source:** `testcases/rewrite_smoke/jumptable_basic.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_basic.ll`
- **Symbol:** `jumptable_basic_target`
- **Native driver:** `rewrite-regression-work/eq/jumptable_basic_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jumptable_basic_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 10 | 10 | 10 | yes | case 0 |
| 2 | RCX=1 | 20 | 20 | 20 | yes | case 1 |
| 3 | RCX=2 | 30 | 30 | 30 | yes | case 2 |
| 4 | RCX=3 | 40 | 40 | 40 | yes | case 3 |
| 5 | RCX=4 | 999 | 999 | 999 | yes | default (>3) |
| 6 | RCX=100 | 999 | 999 | 999 | yes | default far |

## Source

```nasm
default rel
bits 64

global start
global jumptable_basic_target
extern ExitProcess

section .text
; Real indirect jump table on symbolic ECX input.
; ecx 0 -> 10, 1 -> 20, 2 -> 30, 3 -> 40, else -> 999
; The jump is: jmp [jt_basic + rax*8]
; This is the pattern MSVC generates with /O2 for dense switches.
jumptable_basic_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx       ; eax = symbolic input
    cmp eax, 3
    ja jt_b_default     ; unsigned compare: if >3, default
    lea rcx, [jt_basic] ; base of jump table
    jmp [rcx + rax*8]   ; indirect jump through table

jt_b_case0:
    mov eax, 10
    jmp jt_b_done
jt_b_case1:
    mov eax, 20
    jmp jt_b_done
jt_b_case2:
    mov eax, 30
    jmp jt_b_done
jt_b_case3:
    mov eax, 40
    jmp jt_b_done
jt_b_default:
    mov eax, 999
jt_b_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 2
    call jumptable_basic_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
; Jump table: 4 entries (cases 0-3), absolute 64-bit pointers.
jt_basic:
    dq jt_b_case0
    dq jt_b_case1
    dq jt_b_case2
    dq jt_b_case3
```
