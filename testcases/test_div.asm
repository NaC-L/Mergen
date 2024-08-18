section .text

global test_div_64
test_div_64:
mov rdx, 0xbf01
mov rax, 0x800000007F65B9DD
mov rcx, rax
mov rax, 0x11
div rcx
ret

global test_div_32
test_div_32:
mov edx, 0x12345678
mov ecx, 0x1000
mov eax, 0x87654321
div ecx
ret

global test_div_16
test_div_16:
mov dx, 0x1234
mov ax, 0x5678
mov cx, 0x100
div cx
ret

global test_div_8
test_div_8:
mov ax, 0x1278
mov cl, 0x10
div cl
ret