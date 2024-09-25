section .text

global main
main:
cmp rax, 1
push rax
jz condition_taken_zf
pop rax
push rcx
pop rax
ret

condition_taken_zf:
pop rax
inc rax
cond_not_taken_zf:      
ret		

