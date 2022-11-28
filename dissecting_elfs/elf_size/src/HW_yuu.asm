.global _start
.text
_start:
       mov     $1, %al     ; RAX holds Syscall 1 (write), I chose al because it's shorter than mov $1, %rax
       mov     %rax, %rdi  ; RDI holds File Handle 1, STDOUT. Again, moving RAX to RDI is shorter than mov $1, %rdi
       mov     $msg, %rsi  ; RSI holds the address of our string buffer.
       mov     $11, %dl    ; RDX holds the size our of string buffer. Moving into %dl to save space.
       syscall             ; Invoke a syscall with these arguments.

       mov     $60, %al    ; Now we are invoking syscall 60.
       xor     %rdi, %rdi  ; Zero out RDI, which holds the return value.
       syscall             ; Call the system again to exit.
msg:
       .ascii "[^0^] u!!\n" ; all credits belong to @dmxinajeansuit/yuu#8716
