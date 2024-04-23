section .text


global main
main:    ; assume rsp is 24
push rdx ; 0x1122334455667788 -> [16] 88 77 66 55-[19] 44 33 22 11 [23] 
push rcx ; 0x8877665544332211 -> [8]  11 22 33 44 [12]-55 66 77 88 [15]
mov word [rsp+8], ax
mov rax, [rsp+4] ; [12] to [19] 55 66 77 88 88 77 66 55 -> 0x55667788_88776655
pop rcx
pop rdx
ret


