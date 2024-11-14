section .text


; The idea is taking
; %0 = add 10, %a
; %1 = add 5, %0
; and transforming to
; %0 = add %a, 10
; %1 = add %0, 5
; now we can check if RHS is a constant, and fold the instruction
; %0 = add %a, 15

global main
main:
mov rax, 10
add rax, rcx
sub rax, rcx
ret		