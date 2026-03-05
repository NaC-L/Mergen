default rel
bits 64

global start
global nested_branch_target
extern ExitProcess

section .text
; 3-way nested if/else on symbolic RCX input.
; if ecx <= 10 → 100
; else if ecx <= 20 → 200
; else → 300
; All comparisons survive as symbolic selects/phis in IR.
nested_branch_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 10
    jg .above10
    mov eax, 100
    jmp .done
.above10:
    cmp eax, 20
    jg .above20
    mov eax, 200
    jmp .done
.above20:
    mov eax, 300
.done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 15
    call nested_branch_target
    mov ecx, eax
    call ExitProcess
