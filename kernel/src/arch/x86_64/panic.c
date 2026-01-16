#include <arch/cpu_local.h>
#include "common/ipi.h"
#include <common/process.h>
#include <common/cpu_local.h>
#include <arch/hardware/lapic.h>
#include <common/arch.h>
#include <common/interrupts.h>
#include <memory/vmm.h>
#include <stdio.h>
#include <arch/internal/cr.h>

const char* name_table[22] = { "Divide Error",
                               "Debug Exception",
                               "NMI Interrupt",
                               "Breakpoint",
                               "Overflow",
                               "BOUND Range Exceeded",
                               "Undefined Opcode",
                               "Device Not Available (No Math Coprocessor)",
                               "Double Fault",
                               "Coprocessor Segment Overrun",
                               "Invalid TSS",
                               "Segment Not Present",
                               "Stack-Segment Fault",
                               "General Protection ",
                               "Page Fault",
                               "Reserved",
                               "x87 FPU Floating-Point Error",
                               "Alignment Check",
                               "Machine Check",
                               "SIMD Floating-Point Exception",
                               "Virtualization Exception",
                               "Control Protection Exception" };

__attribute__((noreturn)) void arch_panic_int(interrupt_frame_t* frame) {
    disable_interrupts();
    ipi_t ipi;
    ipi.type = IPI_DIE;
    ipi_broadcast_async(&ipi);
    int apic_id = lapic_get_id();

    if(frame->vector == 0x0E) {
        int page_protection_violation = ((frame->error & 0b00000001) > 0);
        int write_access = ((frame->error & 0b00000010) > 0);
        int user_mode = ((frame->error & 0b00000100) > 0);
        int reserved_bit = ((frame->error & 0b00001000) > 0);
        int instruction_fetch = ((frame->error & 0b00010000) > 0);
        int protection_key = ((frame->error & 0b00100000) > 0);
        int shadow_stack = ((frame->error & 0b01000000) > 0);
        int sgx = ((frame->error & 0b0100000000000000) > 0);
        printf("Page fault @ 0x%016llx [ppv=%d, write=%d, ring3=%d, resv=%d, fetch=%d, pk=%d, ss=%d, sgx=%d, wp=%d, smap=%d]", __read_cr2(), page_protection_violation, write_access, user_mode, reserved_bit, instruction_fetch, protection_key, shadow_stack, sgx, arch_get_wp(), arch_get_uap());
    } else if(frame->vector == 0x0D) {
        if(frame->error == 0) {
            printf("General Protection Fault (0x%x | no error code)", frame->vector);
        } else {
            printf("General Protection Fault (0x%x | 0x%lx)", frame->vector, frame->error);
            if(frame->error & 0x1) {
                printf("  [external event]");
            }
            if(frame->error & 0x2) {
                printf(" [idt]");
            } else if(frame->error & 0x4) {
                printf(" [ldt]");
            } else {
                printf(" [gdt]");
            }
            printf(" [index=0x%x]", (frame->error & 0xFFF8) >> 4);
        }
    } else if(frame->vector <= 21) {
        printf("%s (0x%x | %d)", name_table[frame->vector], frame->vector, frame->error);
    } else {
        printf("unknown (0x%x | %d)", frame->vector, frame->error);
    }
    printf(" on core %d in ring %d\n", apic_id, (frame->cs & 0b11));
    if((frame->cs & 0b11) == 3) {
        thread_t* current_thread = CPU_LOCAL_READ(current_thread);
        printf("In userspace process %d:%d\n", current_thread->thread_common.process->pid, current_thread->thread_common.tid);
    }
    printf("rax = 0x%016llx, rbx = 0x%016llx\n", frame->rax, frame->rbx);
    printf("rcx = 0x%016llx, rdx = 0x%016llx\n", frame->rcx, frame->rdx);
    printf("rsi = 0x%016llx, rdi = 0x%016llx\n", frame->rsi, frame->rdi);
    printf("r8  = 0x%016llx, r9  = 0x%016llx\n", frame->r8, frame->r9);
    printf("r10 = 0x%016llx, r11 = 0x%016llx\n", frame->r10, frame->r11);
    printf("r12 = 0x%016llx, r13 = 0x%016llx\n", frame->r12, frame->r13);
    printf("r14 = 0x%016llx, r15 = 0x%016llx\n", frame->r14, frame->r15);

    printf("\n");
    printf("cs  = 0x%016llx, rip = 0x%016llx\n", frame->cs, frame->rip);
    printf("ss  = 0x%016llx, rsp = 0x%016llx\n", frame->ss, frame->rsp);
    printf("rbp = 0x%016llx, rflags = 0x%016llx\n", frame->rbp, frame->rflags);

    uint64_t cr0 = __read_cr0();
    uint64_t cr2 = __read_cr2();
    uint64_t cr3 = __read_cr3();
    uint64_t cr4 = __read_cr4();
    uint64_t cr8 = __read_cr8();

    uint64_t kernel_cr3 = kernel_allocator.kernel_paging_structures_base;

    printf("\n");
    printf("cr0 = 0x%016llx\n", cr0);
    printf("cr2 = 0x%016llx [faulting address]\n", cr2);
    printf("cr3 = 0x%016llx", cr3);
    if(cr3 == kernel_cr3) {
        printf(" [main kernel page table]\n");
    } else {
        printf(" [other page table]\n");
    }
    printf("cr4 = 0x%016llx [todo]\n", cr4);
    printf("cr8 = 0x%016llx [tpl=%d]\n", cr8);

    printf("\n\nWell uhhhh what now?\n");

    while(1) {
        __builtin_ia32_pause();
        asm volatile("hlt");
    }
    __builtin_unreachable();
}
