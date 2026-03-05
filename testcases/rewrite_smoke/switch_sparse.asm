default rel
bits 64

global start
global switch_sparse_target
extern ExitProcess

section .text
; Sparse switch on symbolic ECX input.
; Case values are NOT consecutive: 10, 50, 200, 1000.
; Tests multi-target branch resolution with large gaps between cases.
switch_sparse_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 10
    je .case10
    cmp eax, 50
    je .case50
    cmp eax, 200
    je .case200
    cmp eax, 1000
    je .case1000
    ; default
    mov eax, -1
    jmp .done
.case10:
    mov eax, 11
    jmp .done
.case50:
    mov eax, 55
    jmp .done
.case200:
    mov eax, 222
    jmp .done
.case1000:
    mov eax, 1337
.done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 200
    call switch_sparse_target
    mov ecx, eax
    call ExitProcess
