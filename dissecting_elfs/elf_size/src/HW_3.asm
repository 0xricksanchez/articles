; HW_3.asm
BITS 64
GLOBAL _start
SECTION .text
_start:
    xor rax, rax
    inc al
    mov bl, 5
    int 0x80