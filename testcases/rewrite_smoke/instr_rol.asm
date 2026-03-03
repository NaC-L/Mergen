default rel
bits 64

global start
global instr_rol_target
extern ExitProcess

section .text
instr_rol_target:
    push rbp
    mov rbp, rsp
    mov eax, 0x11
    rol eax, 1
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_rol_target
    mov ecx, eax
    call ExitProcess
