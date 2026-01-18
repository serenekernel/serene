#include "common/ipi.h"

#include <arch/cpu_local.h>
#include <arch/hardware/lapic.h>
#include <arch/internal/cr.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/interrupts.h>
#include <common/process.h>
#include <memory/vmm.h>
#include <stdio.h>

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
        uint8_t page_protection_violation = ((frame->error & (1 << 0)) > 0);
        uint8_t write_access = ((frame->error & (1 << 1)) > 0);
        uint8_t user_mode = ((frame->error & (1 << 2)) > 0);
        uint8_t reserved_bit = ((frame->error & (1 << 3)) > 0);
        uint8_t instruction_fetch = ((frame->error & (1 << 4)) > 0);
        uint8_t protection_key = ((frame->error & (1 << 5)) > 0);
        uint8_t shadow_stack = ((frame->error & (1 << 6)) > 0);
        uint8_t sgx = ((frame->error & (1 << 15)) > 0);
        printf(
            "Page fault @ 0x%016llx [ppv=%d, write=%d, ring3=%d, resv=%d, fetch=%d, pk=%d, ss=%d, sgx=%d, wp=%d, smap=%d]\n",
            __read_cr2(),
            page_protection_violation,
            write_access,
            user_mode,
            reserved_bit,
            instruction_fetch,
            protection_key,
            shadow_stack,
            sgx,
            arch_get_wp(),
            arch_get_uap()
        );

        if(reserved_bit) {
            printf("Reserved bit in page table entry\n");
        } if(protection_key) {
            printf("Protection key violation\n");
        } else {
            const char* who = user_mode ? "User Process" : "Kernel";
            const char* access = write_access ? "write" : "read";
            if(instruction_fetch) {
                access = "execute";
            }
            const char* reason = page_protection_violation ? "non-writeable" : "non-present";
            
            if(instruction_fetch) {
                reason = "non-executable";
            }

            printf("%s tried to %s a %s page\n", who, access, reason);
        }
    } else if(frame->vector == 0x0D) {
        if(frame->error == 0) {
            printf("General Protection Fault (0x%x | no error code)\n", frame->vector);
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
            printf(" [index=0x%x)\n", (frame->error & 0xFFF8) >> 4);
        }
    } else if(frame->vector <= 21) {
        printf("%s (0x%x | %d)\n", name_table[frame->vector], frame->vector, frame->error);
    } else {
        printf("unknown (0x%x | %d)\n", frame->vector, frame->error);
    }
    printf("Core: %d | Ring: %d\n", apic_id, (frame->cs & 0b11));
    if((frame->cs & 0b11) == 3) {
        thread_t* current_thread = CPU_LOCAL_READ(current_thread);
        printf("In userspace process %d:%d\n", current_thread->thread_common.process->pid, current_thread->thread_common.tid);
    }
    printf("\n");
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

    arch_disable_uap();

    virt_addr_t stack_frame_ptr = frame->rbp;
    printf("\nStack backtrace:\n");
    for(int i = 0; i < 16; i++) {
        if(stack_frame_ptr == 0) {
            break;
        }
        
        virt_addr_t new_stack_frame_ptr = *(virt_addr_t*)stack_frame_ptr;
        virt_addr_t return_address = *(virt_addr_t*)(stack_frame_ptr + 8);

        if(return_address == 0 || new_stack_frame_ptr == 0) {
            break;
        }

        printf("  0x%016llx (next instruction)\n", return_address);
        stack_frame_ptr = new_stack_frame_ptr;
    }

    printf("\n\nWell uhhhh what now?\n");

    while(1) {
        __builtin_ia32_pause();
        asm volatile("hlt");
    }
    __builtin_unreachable();
}
