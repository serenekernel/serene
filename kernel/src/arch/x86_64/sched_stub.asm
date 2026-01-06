global __context_switch

__context_switch:
    ; sysv abi says the callee saves these registers:
    ; rbx, rsp, rbp, r12, r13, r14, and r15
    ; the rest (INCLUDING SSE/AVX REGISTERS) are caller-saved

    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; @todo: this is so fucking flimsy it's not even funny
    mov qword [rdi + 0x8], rsp   ; save current rsp to old thread struct
    mov rsp, [rsi + 0x8]         ; load new rsp from new thread struct

    xor rbx, rbx 
    ; software MIGHT of changed ds and es so we should clear them before that could become an issue
    ; cs & ss are handled by sysexit
    ; gs & fs are handled before this function is called
    mov ds, rbx
    mov es, rbx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ret

global __userspace_init
__userspace_init:
    mov rcx, rdi    
    cli
    swapgs

    mov rsp, rsi

    xor rax, rax
    xor rbx, rbx
	xor rdx, rdx
	xor rsi, rsi
	xor rdi, rdi
	xor r8, r8
	xor r9, r9
	xor r10, r10
	xor r12, r12
	xor r13, r13
	xor r14, r14
	xor r15, r15
    xor rbp, rbp

    mov r11, 0x202 ; interrupts enabled
    o64 sysret