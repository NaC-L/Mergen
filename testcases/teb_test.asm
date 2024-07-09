section .text

global main
main:
mov rax, fs:[0x30]
ret