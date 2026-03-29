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
