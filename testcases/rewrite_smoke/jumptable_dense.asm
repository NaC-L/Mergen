default rel
bits 64

global start
global jumptable_dense_target
extern ExitProcess

section .text
; 8-way dense jump table on symbolic ECX input.
; ecx 0->100, 1->200, 2->300, 3->400, 4->500, 5->600, 6->700, 7->800, else->0
jumptable_dense_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 7
    ja jt_d_default
    lea rcx, [jt_dense]
    jmp [rcx + rax*8]

jt_d_case0:
    mov eax, 100
    jmp jt_d_done
jt_d_case1:
    mov eax, 200
    jmp jt_d_done
jt_d_case2:
    mov eax, 300
    jmp jt_d_done
jt_d_case3:
    mov eax, 400
    jmp jt_d_done
jt_d_case4:
    mov eax, 500
    jmp jt_d_done
jt_d_case5:
    mov eax, 600
    jmp jt_d_done
jt_d_case6:
    mov eax, 700
    jmp jt_d_done
jt_d_case7:
    mov eax, 800
    jmp jt_d_done
jt_d_default:
    mov eax, 0
jt_d_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 5
    call jumptable_dense_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
; Dense jump table: 8 entries (cases 0-7)
jt_dense:
    dq jt_d_case0
    dq jt_d_case1
    dq jt_d_case2
    dq jt_d_case3
    dq jt_d_case4
    dq jt_d_case5
    dq jt_d_case6
    dq jt_d_case7
