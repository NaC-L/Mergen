section .text

global main
main:
xor rcx, rcx

do_loop:
add rcx, rcx
inc rcx
cmp rcx, 1000
jbe do_loop

ret		