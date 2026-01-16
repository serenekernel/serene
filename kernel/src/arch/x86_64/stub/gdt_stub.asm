global __load_gdt

__load_gdt:
    lgdt [rdi]
    push rsi
    lea rax, .reload_cs
    push rax
    retfq
.reload_cs:
    mov ds, dx
    mov es, dx
    mov ss, dx
    ltr cx
    ret 