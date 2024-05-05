section .text

global main_2
main_2:    ; assume rsp is 24
mov rdx, 0xffffffffffffffff ;
mov ecx, 0x2222
push rdx;						   [16] FF [17] FF [18] FF FF [19] FF [20] FF FF [22] FF [23]
mov dword [rsp-1], ecx ;  [15] 22  [16] 22-[17] 11 [18] 11 FF [19] FF-[20] FF FF [22] FF [23]
mov rax, [rsp] ; 				   [16] 22-[17] 11 [18] 11 FF [19] FF-[20] FF FF [22] FF [23] 
pop rdx							   ;0xFF_FF_FF_FF_FF_FF_11_11_22
ret

global main
main:    ; assume rsp is 24
mov rdx, 0xffffffffffffffff ;
mov ecx, 0x2222
push rdx;						   [16] FF [17] FF [18] FF FF [19] FF [20] FF FF FF [23]
mov word [rsp+2], cx   ;  [15] FF  [16] FF-[17] FF [18] 22 22 [19] FF-[20] FF FF FF [23]
mov rax, [rsp] ; 				   [16] FF-[17] FF [18] 22 22 [19] FF-[20] FF FF FF [23]
pop rdx
ret								   ;0xFF_FF_FF_FF_22_22_FF_FF



global main_
main_:    ; assume rsp is 24
mov rdx, 0xffffffffffffffff ;
mov ecx, 0x2222
push rdx;						   [16] FF [17] FF [18] FF FF [19] FF [20] FF FF [22] FF [23]
mov word [rsp+7], cx   ;  [15] FF  [16] FF-[17] FF [18] FF FF [19] FF-[20] FF FF [22] 22 [23] 22 [24]
mov rax, [rsp] ; 				   [16] FF-[17] FF [18] FF FF [19] FF-[20] FF FF [22] 22 [23] 22 [24]
pop rdx							   ;0x22_FF_FF_FF_FF_FF_FF_FF_FF
ret


global main3
main3:    ; assume rsp is 24
mov rdx, 0x1122334455667788 ;
mov rcx, 0x44444444 ;
push rdx ; 0x1122334455667788 -> [16] 88 [17] 77 66 55-[19] 44 [20] 33 22 11 [23]
mov dword [rsp+1], ecx ; 		 [16] 88 [17] 44 44 44 [19] 44-[20] 33 22 11 [23]
mov ecx, 0x2222
mov word [rsp-1], cx   ; [15] 22 [16] 22-[17] 44 44 44 [19] 44-[20] 33 22 11 [23]
mov rax, [rsp] ; 				 [16] 22-[17] 44 44 44 [19] 44-[20] 33 22 11 [23]
pop rdx
ret

section .text
global main4
main4:
  mov rax, 0x1122334455667788
  push rax
  mov dword [rsp+4], 0x44332211
  pop rax
  ret

