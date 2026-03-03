default rel
bits 64

global start
global instr_sub_target
extern ExitProcess

section .text
instr_sub_target:
    push rbp
    mov rbp, rsp
    mov eax, 100
    sub eax, 58
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_sub_target
    mov ecx, eax
    call ExitProcess
