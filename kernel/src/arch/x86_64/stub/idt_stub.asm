section .text
global __load_idt
extern x86_64_dispatch_interupt
__load_idt:
   lidt [rdi]
   ret


%macro ISR 1
global isr%1
isr%1:
    push 0
    push %1
    jmp handler_common
%endmacro

%macro ISR_ERROR 1
global isr%1
isr%1:
    push %1
    jmp handler_common
%endmacro

%macro SWAPGS_IF_FROM_RING3 0
        test qword [rsp + 24], 3
        jz %%noswap
        swapgs
    %%noswap:
%endmacro

handler_common:
    cld

    SWAPGS_IF_FROM_RING3

    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    call x86_64_dispatch_interupt

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    SWAPGS_IF_FROM_RING3
    add rsp, 16
    iretq

             ; Num | Type      | Has code | Name
ISR       0  ; 0   | Fault 	   | No       | Divide Error 	    
ISR       1  ; 1   | Trap 	   | No       | Debug Exception 	 
ISR       2  ; 2   | Interrupt | No       | NMI Interrupt 	    
ISR       3  ; 3   | Trap 	   | No       | Breakpoint       
ISR       4  ; 4   | Trap 	   | No       | Overflow         
ISR       5  ; 5   | Fault 	   | No       | BOUND Range Exceeded
ISR       6  ; 6   | Fault 	   | No       | Undefined Opcode
ISR       7  ; 7   | Fault 	   | No       | Device Not Available (No Math Coprocessor)
ISR_ERROR 8  ; 8   | Abort 	   | Yeszero  | Double Fault
ISR       9  ; 9   | Fault 	   | No       | Coprocessor Segment Overrun
ISR_ERROR 10 ; A   | Fault 	   | Yes 	  | Invalid TSS
ISR_ERROR 11 ; B   | Fault 	   | Yes 	  | Segment Not Present
ISR_ERROR 12 ; C   | Fault 	   | Yes 	  | Stack-Segment Fault
ISR_ERROR 13 ; D   | Fault 	   | Yes 	  | General Protection 
ISR_ERROR 14 ; E   | Fault 	   | Yes 	  | Page Fault
ISR       15 ; F   | Reserved
ISR       16 ; 10  | Fault 	   | No       | x87 FPU Floating-Point Error
ISR_ERROR 17 ; 11  | Fault 	   | Yeszero  | Alignment Check
ISR       18 ; 12  | Abort 	   | No       | Machine Check
ISR       19 ; 13  | Fault 	   | No       | SIMD Floating-Point Exception
ISR       20 ; 14  | Fault 	   | No       | Virtualization Exception
ISR_ERROR 21 ; 15  | Fault 	   | Yes 	  | Control Protection Exception


%assign i 21
%rep 255 - 21
   %assign i i + 1
   ISR       i
%endrep

section .rodata
global x86_isr_stub_table

x86_isr_stub_table:
%assign i 0
%rep 256
    extern isr%+i
    dq isr%+i
    %assign i i+1
%endrep