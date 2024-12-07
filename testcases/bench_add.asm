section .text

global main
main:
xor rcx, rcx
do_loop:
add rax, rax
inc rcx
cmp rcx, 1000
jbe do_loop
ret		