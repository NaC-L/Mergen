default rel
bits 64

global start
global diamond_target
extern ExitProcess

section .text
; Diamond-shaped CFG: two paths merge then continue.
;   if ecx is odd: eax = ecx + 10
;   else:          eax = ecx - 5
;   then:          eax *= 3
; Symbolic input → expect select/phi at merge, then mul by 3.
diamond_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    test eax, 1
    jz .even
    add eax, 10
    jmp .merge
.even:
    sub eax, 5
.merge:
    imul eax, eax, 3
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 7
    call diamond_target
    mov ecx, eax
    call ExitProcess
