global _start
bits 64

_start:
    mov rdi, 0xdeadbeaf
    mov rsi, 0xe9
    syscall

    mov al, 'h'
    out 0xe9, al

    mov rdi, 0xcafebabe
    syscall
    int3
