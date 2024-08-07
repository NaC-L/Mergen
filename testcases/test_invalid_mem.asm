section .text

global main
main:
mov rax, 10
push rax
call [rsp]
ret