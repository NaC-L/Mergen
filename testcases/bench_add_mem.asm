section .text

global main
main:
xor rcx, rcx
push rax

do_loop:
add [rsp], rax
inc rcx
cmp rcx, 1000
jbe do_loop

pop rax
ret		