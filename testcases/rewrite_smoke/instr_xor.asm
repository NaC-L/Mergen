default rel
bits 64

global start
global instr_xor_target
extern ExitProcess

section .text
instr_xor_target:
    push rbp
    mov rbp, rsp
    mov eax, 0x55
    xor eax, 0x0f
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_xor_target
    mov ecx, eax
    call ExitProcess
