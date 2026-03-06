default rel
bits 64

global start
global bitchain_target
extern ExitProcess

section .text
; Pure-constant bit manipulation chain. No symbolic inputs.
; eax = 0xFF
; shl eax, 8   → 0x0000FF00
; xor eax, 0xAA → 0x0000FFAA
; ror eax, 4   → 0xA0000FFA
; and eax, 0xFFFF → 0x0FFA = 4090
; LLVM must fold entire chain to ret i64 4090.
bitchain_target:
    push rbp
    mov rbp, rsp
    mov eax, 0xFF
    shl eax, 8
    xor eax, 0xAA
    ror eax, 4
    and eax, 0xFFFF
    pop rbp
    ret

start:
    sub rsp, 40
    call bitchain_target
    mov ecx, eax
    call ExitProcess
