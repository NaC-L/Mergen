section .text

global main
main:
sub rsp, 0x200
mov rax, rsp
and rcx, 1
lea rax, [rax+rcx*8]
mov [rax], rcx
add rsp, 0x200
ret