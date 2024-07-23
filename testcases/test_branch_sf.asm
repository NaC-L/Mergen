section .text

global main
main:
cmp rax, 0 				; zf = rax-0 == 0 ; sf = rax-0 < 0; of = (rax ^ 0) < 0; ....

jns cond_not_taken_sf   ; sf == 0; if not taken, we can say rax is negative, so rax | 18446744073709551616 (sign bit is set)

condition_taken_sf: 	; so the basic block here will assume rax's msb is set

shr rax, 63 			; rax will be 1

cond_not_taken_sf:      ; but this basicblock wont assume rax is 0

ret		