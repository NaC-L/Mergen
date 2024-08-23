section .text

global main
main:
or rax, 1
shl rax, 1
shr rax, 1
cmp rax, 0
pushf
mov rax, qword [rsp]
and rax, 0x40
add rsp, 8
ret