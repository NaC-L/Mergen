section .text

global main
main:
cmp rax, 0 				; zf = rax-0 == 0 ; sf = rax-0 < 0; of = (rax ^ 0) < 0; ....

jnz cond_not_taken_zf   ; zf == 0; if not taken, we can say rax is 0 for this branch, we can do this by rax & 0.

condition_taken_zf: 	; so the basic block here will assume rax is 0

inc rax    				; rax will be 1

cond_not_taken_zf:      ; but this basicblock wont assume rax is 0

ret		

