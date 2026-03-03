default rel
bits 64

global start
global branch_target
extern ExitProcess

section .text
branch_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 5
    jg .gt
    add eax, 100
    jmp .done
.gt:
    imul eax, eax, 3
.done:
    xor eax, 0x33
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 10
    call branch_target
    mov ecx, eax
    call ExitProcess
