section .text

global main
main:
xor rcx, rcx
push rcx

do_loop:
add [rsp], rcx
inc rcx
cmp rcx, 1000
jbe do_loop

pop rax
ret		