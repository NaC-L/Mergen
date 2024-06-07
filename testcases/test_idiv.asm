section .text

global main
main:
mov rdx, 0xbf01
mov rax, 0x800000007F65B9DD
mov rcx, rax
mov rax, 0x11
idiv rcx
ret