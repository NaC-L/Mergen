default rel
bits 64

global start
global jumptable_rel32_target
extern ExitProcess

section .text
; RIP-relative 32-bit offset jump table — the pattern MSVC /O2 actually
; generates for x64 switch statements.
;
; Pattern:
;   lea  rdx, [rip + jt_data]      ; table base
;   movsxd rax, dword [rdx + rcx*4]; signed 32-bit offset from table base
;   add  rax, rdx                   ; absolute target
;   jmp  rax                        ; indirect jump
;
; ecx 0->10, 1->20, 2->30, 3->40, 4->50, else->999
jumptable_rel32_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 4
    ja .default
    lea rdx, [.jt_data]
    movsxd rax, dword [rdx + rcx*4]
    add rax, rdx
    jmp rax

.case0:
    mov eax, 10
    jmp .done
.case1:
    mov eax, 20
    jmp .done
.case2:
    mov eax, 30
    jmp .done
.case3:
    mov eax, 40
    jmp .done
.case4:
    mov eax, 50
    jmp .done
.default:
    mov eax, 999
.done:
    pop rbp
    ret

; Table lives in .text so NASM can compute intra-section differences.
align 4
.jt_data:
    dd .case0 - .jt_data
    dd .case1 - .jt_data
    dd .case2 - .jt_data
    dd .case3 - .jt_data
    dd .case4 - .jt_data

start:
    sub rsp, 40
    mov ecx, 3
    call jumptable_rel32_target
    mov ecx, eax
    call ExitProcess
