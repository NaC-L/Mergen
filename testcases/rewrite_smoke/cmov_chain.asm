default rel
bits 64

global start
global cmov_chain_target
extern ExitProcess

section .text
; Conditional moves (branchless select) on symbolic RCX:
;   eax = 100, edx = 200
;   if ecx > 10: eax = edx (200)
;   eax += 50
; Result is 150 or 250 depending on input.
; No branches in the CFG — cmov emits a select directly.
; Expect: select i1, add.
cmov_chain_target:
    push rbp
    mov rbp, rsp
    mov eax, 100
    mov edx, 200
    cmp ecx, 10
    cmovg eax, edx
    add eax, 50
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 15
    call cmov_chain_target
    mov ecx, eax
    call ExitProcess
