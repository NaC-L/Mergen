default rel
bits 64

global start
global jumptable_shared_target
extern ExitProcess

section .text
; Jump table with shared case targets: multiple indices route to the
; same handler.  Tests that the lifter correctly merges equivalent
; table entries.
;
; ecx 0->10, 1->10, 2->20, 3->30, 4->30, 5->40, else->999
jumptable_shared_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 5
    ja jtsh_default
    lea rcx, [jtsh_table]
    jmp [rcx + rax*8]

jtsh_group_a:               ; cases 0, 1
    mov eax, 10
    jmp jtsh_done
jtsh_solo_b:                ; case 2
    mov eax, 20
    jmp jtsh_done
jtsh_group_c:               ; cases 3, 4
    mov eax, 30
    jmp jtsh_done
jtsh_solo_d:                ; case 5
    mov eax, 40
    jmp jtsh_done
jtsh_default:
    mov eax, 999
jtsh_done:
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 4
    call jumptable_shared_target
    mov ecx, eax
    call ExitProcess

section .rdata
align 8
jtsh_table:
    dq jtsh_group_a     ; case 0
    dq jtsh_group_a     ; case 1  (shared with 0)
    dq jtsh_solo_b      ; case 2
    dq jtsh_group_c     ; case 3
    dq jtsh_group_c     ; case 4  (shared with 3)
    dq jtsh_solo_d      ; case 5
