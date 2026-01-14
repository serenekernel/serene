global __handle_syscall
extern dispatch_syscall
__handle_syscall:
    swapgs

    mov r15, qword [gs:0]
    mov qword [r15 + 8], rsp
    mov rsp, qword [r15 + 16]

    ; @note:
    ; save registers - 14 registers = 112 bytes
    ; kernel stack starts 16-byte aligned
    ; after 14 pushes (112 bytes = 7*16), stack is still 16-byte aligned
    ; but call will push return address (8 bytes), making it misaligned
    ; so we need to adjust by 8 bytes before the pushes
    ; 
    ; sub rsp, 8      ; @note: align stack for call instruction
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    
    ; the sysv exepects the args to be in rdi, rsi, rdx, rcx, r8, r9
    ; where rdi is the syscall number and another other args are general purpose

    ; but syscall clobbers rcx so we make usermode programs deal with amd's bullshit
    mov rcx, r10

    sti
    call dispatch_syscall
    cli

    xor rdx, rdx

    xor r12, r12
    mov r12, ds
    mov r12, es

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx

    ; add rsp, 8      ; remove alignment adjustment


    mov rsp, qword [r15 + 8]
    xor r15, r15

    swapgs
    o64 sysret
