; HW_2.asm
BITS 64
GLOBAL _start
SECTION .text
_start:
    mov eax, 1
    mov ebx, 5
    int 0x80