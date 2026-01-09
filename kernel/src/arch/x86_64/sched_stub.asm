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
    mov qword [rdi + 0x8], rsp   ; save current rsp to old thread struct
    mov rsp, [rsi + 0x8]         ; load new rsp from new thread struct

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

; void __userspace_init();
global __userspace_init
__userspace_init:
    pop rcx ; address to sysret
    cli
    swapgs

    pop rax ; userspace stack pointer
    mov rsp, rax

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

; void __jump_to_idle_thread(virt_addr_t stack_ptr, virt_addr_t entry_point);
; stack_ptr in rdi (points to prepared context switch frame)
; entry_point in rsi (not used, already in stack frame)
global __jump_to_idle_thread
__jump_to_idle_thread:
    ; Load the idle thread's prepared stack
    ; The stack has the context switch frame: rbx, rbp, r12, r13, r14, r15, return_addr
    mov rsp, rdi

    ; Pop the saved registers (they're all zero from initialization)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ; Enable interrupts before jumping to idle thread
    sti

    ; Return will jump to the entry point that's on top of stack
    ret
