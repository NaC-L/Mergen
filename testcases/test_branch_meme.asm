section .text

%define SF 0x80

global main
main:
and rsi, 1
lea rcx, [rel jtable]
mov rax, [rcx+rsi*4]
lea rax, [rcx+rax]
jmp rax


jtable: dd      test1 - jtable
		dd      test2 - jtable

test1:
xor rax, rax
or rax, rsi
ret
test2:
xor rax, rax
or rax, rsi
inc rax
ret