section .text

global main
main:
cmp rax, 1 				; zf = rax-0 == 0 ; sf = rax-0 < 0; of = (rax ^ 0) < 0; ....

jz condition_taken_zf   ; zf == 0; if not taken, we can say rax is 0 for this branch, we can do this by rax & 0.
ret
condition_taken_zf: 	; so the basic block here will assume rax is 0

inc rax    				; rax will be 1

cond_not_taken_zf:      ; but this basicblock wont assume rax is 0

ret		


main2:
lea rcx, [rcx+rax]      
cmp rax, 0              
condition_taken_zf2: 	; so the basic block here will assume rax is 0
inc rax    				; rax will be 1
add rax, rcx			; rcx + 1, not rcx+rax+1
cond_not_taken_zf2:      ; but this basicblock wont assume rax is 0
ret		

; %a = rcx + rax
; %zf = rax == 0
; rax_zero.bb:
; %inc = 0 + 1   ; simplified to 1
; %b = %a + %inc ; %a can be simplified to %rcx
; ret %b

; rax_nonzero.bb
; ret %rax

; we can only say something sure about what generates the flag, in this case, its cmp rax, 0
; so 
; %zf0 = %v - 0 
; %zf1 = %zf0 == 0
; we can only assume the value of %zf0 because we check %zf1
; so %zf0 should be 0
; by extension %v should be 0
;

; if it was
; cmp rax, rcx
; then
; %zf0 = %rax - %rcx
; %zf1 = %zf0 == 0
; we can only assume %zf0 is 0 (if true)
;