section .text


global main
main:
push rdx
push rcx
mov rax, [rsp+4]
pop rdx
pop rcx
ret

