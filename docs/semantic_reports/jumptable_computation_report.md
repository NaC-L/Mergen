# jumptable_computation - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 7/7 equivalent
- **Source:** `testcases/rewrite_smoke/jumptable_computation.asm`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/jumptable_computation.ll`
- **Symbol:** `jumptable_computation_target`
- **Native driver:** `rewrite-regression-work/eq/jumptable_computation_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `jumptable_computation_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | case 0: 0*2+1 |
| 2 | RCX=1 | 8 | 8 | 8 | yes | case 1: 1*3+5 |
| 3 | RCX=2 | 18 | 18 | 18 | yes | case 2: 2*4+10 |
| 4 | RCX=3 | 103 | 103 | 103 | yes | case 3: 3+100 |
| 5 | RCX=4 | 0 | 0 | 0 | yes | default (>3) |
| 6 | RCX=100 | 0 | 0 | 0 | yes | default far |
| 7 | RCX=5 | 0 | 0 | 0 | yes | default (5 > 3) |

## Source

```nasm
default rel
bits 64

global start
global jumptable_computation_target
extern ExitProcess

section .text
; Jump table where case bodies compute on the symbolic input, not just
; return constants.  Tests that the lifter preserves the input value
; across the jump table dispatch and into the case body.
;
; The original input (ecx) is saved in r8d before the table jump.
;
; ecx 0 -> ecx*2 + 1
; ecx 1 -> ecx*3 + 5
; ecx 2 -> ecx*4 + 10
; ecx 3 -> ecx + 100
; else  -> 0
jumptable_computation_target:
    push rbp
    mov rbp, rsp
    mov r8d, ecx            ; save original input
    mov eax, ecx
    cmp eax, 3
    ja jtc_default
    lea rcx, [jtc_table]
    jmp [rcx + rax*8]

jtc_case0:                     ; result = input * 2 + 1
    lea eax, [r8d + r8d + 1]
    jmp jtc_done
jtc_case1:                     ; result = input * 3 + 5
    lea eax, [r8d + r8d*2 + 5]
    jmp jtc_done
jtc_case2:                     ; result = input * 4 + 10
    shl r8d, 2
    lea eax, [r8d + 10]
    jmp jtc_done
jtc_case3:                     ; result = input + 100
    lea eax, [r8d + 100]
    jmp jtc_done
jtc_default:
    xor eax, eax
jtc_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 2
    call jumptable_computation_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
jtc_table:
    dq jtc_case0
    dq jtc_case1
    dq jtc_case2
    dq jtc_case3
```
