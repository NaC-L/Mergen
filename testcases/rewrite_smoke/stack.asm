default rel
bits 64

global start
global stack_target
extern ExitProcess

section .text
stack_target:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov dword [rsp + 16], 0x11111111
    mov eax, dword [rsp + 16]
    add eax, 0x22222222
    rol eax, 1
    add rsp, 32
    pop rbp
    ret

start:
    sub rsp, 40
    call stack_target
    mov ecx, eax
    call ExitProcess
