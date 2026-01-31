global __context_switch

; void __context_switch(thread_t* old_thread, thread_t* new_thread, uint64_t status);
; old_thread in rdi
; new_thread in rsi
; status in rdx
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
    mov qword [rdi + 16], rsp   ; save current rsp to old thread struct
    mov rsp, [rsi + 16]         ; load new rsp from new thread struct

    mov [rdi + 0x30], rdx        ; load status into the thread struct - we NEED to do this in the case of termination because otherwise the reaper thread can kill us BEFORE we get to this point and then we'll be very fucked

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
    sti
    ret

__userspace_exit_common:
    ; return address of whatever called us
    ; since we fuck with the stack we gotta grab this rq
    pop r10

    ; INTEL WHY DID YOU MAKE THIS TAKE A MEMORY OPERAND ONLY
    mov rcx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (0b11 << 8)
    push rcx 
    fldcw [rsp]

    mov rcx, (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)
    push rcx
    ldmxcsr [rsp]

    ; clean up fpu stack
    add rsp, 16

    pop rcx ; address to sysret to
    pop rax ; userspace stack pointer
    push r10 ; push this back on the stack so ret can use it

    ; bye bye regs
    ; @note: we don't bother clearing rbx, rbp, r12, r13, r14, r15 
    ; because they should be cleared by the context switch
    ; we also don't clear rax because it's going to be used for sysret & fred
	xor rdx, rdx
	xor rsi, rsi
	xor rdi, rdi
	xor r8, r8
	xor r9, r9
	xor r10, r10

    mov r11, 0x202 ; interrupts enabled
    ret

; void __userspace_init_sysexit();
global __userspace_init_sysexit
__userspace_init_sysexit:
    cli
    call __userspace_exit_common
    
    mov rsp, rax
    xor rax, rax
    
    swapgs
    o64 sysret

; void __userspace_init_fred();
global __userspace_init_fred
__userspace_init_fred:
    cli
    call __userspace_exit_common

    push qword 0x20 | 3
    push qword rax
    push qword r11
    push qword 0x28 | 3
    push qword rcx
    push qword 0

    xor rax, rax
    eretu

; void __jump_to_idle_thread(virt_addr_t stack_ptr, virt_addr_t entry_point);
; stack_ptr in rdi (points to prepared context switch frame)
; entry_point in rsi (not used, already in stack frame)
global __jump_to_idle_thread
__jump_to_idle_thread:
    ; Load the idle thread's prepared stack
    ; The stack has the context switch frame: rbx, rbp, r12, r13, r14, r15, return_addr
    mov rsp, rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    sti
    ret
