#include "arch/internal/cr.h"
#include "arch/interrupts.h"
#include "arch/msr.h"
#include "common/arch.h"

#include <arch/internal/gdt.h>
#include <common/cpu_local.h>
#include <common/userspace.h>
#include <lib/assert.h>
#include <memory/memory.h>

extern void x86_64_fred_ring3_entry_stub();

#define FRED_STACK_LEVEL_VALUE(vector, level) (((uint64_t) (level) & 0x3) << ((vector) * 2))

void setup_fred_bsp() {
    tss_t* tss = CPU_LOCAL_READ(cpu_tss);
    arch_memory_barrier();
    uint64_t cr4 = __read_cr4();
    cr4 |= (1ull << 32); // Enable FRED
    __write_cr4(cr4);
    arch_memory_barrier();

    __wrmsr(IA32_FRED_CONFIG, (uint64_t) x86_64_fred_ring3_entry_stub);
    __wrmsr(IA32_FRED_RSP0, (uint64_t) tss->rsp0);
    __wrmsr(IA32_FRED_RSP1, (uint64_t) tss->ist[1]); // #NMI
    __wrmsr(IA32_FRED_RSP2, (uint64_t) tss->ist[2]); // #DF
    __wrmsr(IA32_FRED_RSP3, (uint64_t) tss->ist[3]); // #MC

    uint64_t fred_stack_level = 0;
    fred_stack_level |= FRED_STACK_LEVEL_VALUE(0x02, 1); // #NMI
    fred_stack_level |= FRED_STACK_LEVEL_VALUE(0x08, 2); // #DF
    fred_stack_level |= FRED_STACK_LEVEL_VALUE(0x12, 3); // #MC

    __wrmsr(IA32_FRED_STACK_LEVELS, fred_stack_level);
}

void setup_fred_ap() {
    assert(false);
}

extern syscall_ret_t dispatch_syscall(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, syscall_nr_t syscall_nr);
extern void x86_64_dispatch_interrupt(interrupt_frame_t* frame);

void x86_64_fred_entry_ring3(fred_frame_t* frame) {
    uint8_t type = (frame->ss >> 48) & 0xF;

    if(type == 7) {
        syscall_ret_t ret = dispatch_syscall(frame->regs.rdi, frame->regs.rsi, frame->regs.rdx, frame->regs.rcx, frame->regs.r8, frame->regs.r9, (syscall_nr_t) frame->regs.rax);
        frame->regs.rax = ret.value;
        frame->regs.rdx = ret.is_error;
        frame->regs.rcx = 0;
        frame->regs.r11 = 0;
        frame->regs.r15 = 0;
    } else {
        uint8_t vector = (frame->ss >> 32) & 0xFF;
        interrupt_frame_t interrupt_frame;
        interrupt_frame.vector = vector;
        interrupt_frame.error = frame->error;
        interrupt_frame.interrupt_data = frame->fred_event_data;
        interrupt_frame.is_user = true;
        interrupt_frame.internal_frame = (void*) frame;
        interrupt_frame.regs = &frame->regs;

        x86_64_dispatch_interrupt(&interrupt_frame);
    }
}


void x86_64_fred_entry_ring0(fred_frame_t* frame) {
    uint8_t vector = (frame->ss >> 32) & 0xFF;
    interrupt_frame_t interrupt_frame;
    interrupt_frame.vector = vector;
    interrupt_frame.error = frame->error;
    interrupt_frame.interrupt_data = frame->fred_event_data;
    interrupt_frame.is_user = false;
    interrupt_frame.internal_frame = (void*) frame;
    interrupt_frame.regs = &frame->regs;

    x86_64_dispatch_interrupt(&interrupt_frame);
}
