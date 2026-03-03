default rel
bits 64

global start
global instr_add_target
extern ExitProcess

section .text
instr_add_target:
    push rbp
    mov rbp, rsp
    mov eax, 7
    add eax, 5
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_add_target
    mov ecx, eax
    call ExitProcess
