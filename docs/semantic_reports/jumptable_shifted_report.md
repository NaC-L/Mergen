# jumptable_shifted - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 9/9 equivalent
- **Source:** `testcases/rewrite_smoke/jumptable_shifted.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_shifted.ll`
- **Symbol:** `jumptable_shifted_target`
- **Native driver:** `rewrite-regression-work/eq/jumptable_shifted_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jumptable_shifted_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=10 | 100 | 100 | 100 | yes | case 10 |
| 2 | RCX=11 | 200 | 200 | 200 | yes | case 11 |
| 3 | RCX=12 | 300 | 300 | 300 | yes | case 12 |
| 4 | RCX=13 | 400 | 400 | 400 | yes | case 13 |
| 5 | RCX=14 | 500 | 500 | 500 | yes | case 14 |
| 6 | RCX=9 | 0 | 0 | 0 | yes | default (below range) |
| 7 | RCX=15 | 0 | 0 | 0 | yes | default (above range) |
| 8 | RCX=0 | 0 | 0 | 0 | yes | default (zero) |
| 9 | RCX=100 | 0 | 0 | 0 | yes | default far |

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
