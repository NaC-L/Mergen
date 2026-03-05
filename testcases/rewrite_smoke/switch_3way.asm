default rel
bits 64

global start
global switch_3way_target
extern ExitProcess

section .text
; 3-way computed jump on symbolic ECX input.
; if ecx == 1 → return 100
; if ecx == 2 → return 200
; if ecx == 3 → return 300
; else (default) → return 999
; Tests multi-target branch resolution (>2 targets).
switch_3way_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 1
    je .case1
    cmp eax, 2
    je .case2
    cmp eax, 3
    je .case3
    ; default
    mov eax, 999
    jmp .done
.case1:
    mov eax, 100
    jmp .done
.case2:
    mov eax, 200
    jmp .done
.case3:
    mov eax, 300
.done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 2
    call switch_3way_target
    mov ecx, eax
    call ExitProcess
