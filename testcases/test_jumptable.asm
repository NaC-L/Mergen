section .text

%define SF 0x80

global main
main:
sub rcx, 0 ; turn SF if rcx is -
pushfq
pop rsi
and rsi, SF ; check if SF is turned on
shr rsi, 7
lea rcx, [rel jtable]
mov eax, [rcx+rsi*4]
lea rax, [rcx+rax]
push rax
ret


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