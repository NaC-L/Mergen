section .text

global main
main:
push rax
mov dword [rsp+4], ecx
and rcx, 1
mov rax, [rsp]
add rsp, 8
ret		