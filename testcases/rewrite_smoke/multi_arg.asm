default rel
bits 64

global start
global multi_arg_target
extern ExitProcess

section .text
; Two symbolic arguments (RCX, RDX) combined:
;   result = (ecx + edx) * 7
; Since both inputs are symbolic, the IR cannot constant-fold.
; Expect to see add and mul operations in lifted IR.
multi_arg_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    add eax, edx
    imul eax, eax, 7
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 5
    mov edx, 3
    call multi_arg_target
    mov ecx, eax
    call ExitProcess
