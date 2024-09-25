section .text

global main
main:
push rax
push rcx
and rcx, 1
mov rax, [rsp+rcx*8]
add rsp, 16
ret		