#include "arch/internal/cr.h"
#include "arch/interrupts.h"
#include "arch/msr.h"
#include "common/arch.h"

#include <arch/internal/gdt.h>
#include <common/cpu_local.h>
#include <common/userspace.h>
#include <lib/assert.h>
#include <memory/memory.h>

typedef struct fred_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t error, rip, cs, rflags, rsp, ss;
    uint64_t fred_event_data;
    uint64_t fred_reserved;
} fred_frame_t;


extern void x86_64_fred_ring3_entry_stub();

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
    __wrmsr(IA32_FRED_STACK_LEVELS, 0); // @todo
}

void setup_fred_ap() {
    assert(false);
}

extern syscall_ret_t dispatch_syscall(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, syscall_nr_t syscall_nr);
extern void x86_64_dispatch_interrupt(interrupt_frame_t* frame);

// @note: for now this is a compat thing where we convert fred_frame_t to interrupt_frame_t
void convert_from_fred(interrupt_frame_t* dest, fred_frame_t* source) {
    uint8_t vector = (source->ss >> 32) & 0xFF;
    dest->vector = vector;
    dest->rax = source->rax;
    dest->rbx = source->rbx;
    dest->rcx = source->rcx;
    dest->rdx = source->rdx;
    dest->rsi = source->rsi;
    dest->rdi = source->rdi;
    dest->rbp = source->rbp;
    dest->rsp = source->rsp;
    dest->r8 = source->r8;
    dest->r9 = source->r9;
    dest->r10 = source->r10;
    dest->r11 = source->r11;
    dest->r12 = source->r12;
    dest->r13 = source->r13;
    dest->r14 = source->r14;
    dest->r15 = source->r15;

    dest->rip = source->rip;
    dest->cs = source->cs;
    dest->rflags = source->rflags;
    dest->rsp = source->rsp;
    dest->ss = source->ss & 0xFFFF;
    dest->error = source->error;
}
void convert_to_fred(fred_frame_t* dest, interrupt_frame_t* source) {
    dest->rax = source->rax;
    dest->rbx = source->rbx;
    dest->rcx = source->rcx;
    dest->rdx = source->rdx;
    dest->rsi = source->rsi;
    dest->rdi = source->rdi;
    dest->rbp = source->rbp;
    dest->rsp = source->rsp;
    dest->r8 = source->r8;
    dest->r9 = source->r9;
    dest->r10 = source->r10;
    dest->r11 = source->r11;
    dest->r12 = source->r12;
    dest->r13 = source->r13;
    dest->r14 = source->r14;
    dest->r15 = source->r15;

    dest->rip = source->rip;
    dest->cs = source->cs;
    dest->rflags = source->rflags;
    dest->rsp = source->rsp;
    // dest->ss = source->ss; // @note: ss also contains the vector/type info so omited
    dest->error = source->error;
}

void x86_64_fred_entry_ring3(fred_frame_t* frame) {
    uint8_t type = (frame->ss >> 48) & 0xF;

    if(type == 7) {
        dispatch_syscall(frame->rdi, frame->rsi, frame->rdx, frame->rcx, frame->r8, frame->r9, (syscall_nr_t) frame->rax);
    } else {
        // @note: for now this is a compat thing where we convert fred_frame_t to interrupt_frame_t
        interrupt_frame_t new_frame;
        convert_from_fred(&new_frame, frame);
        x86_64_dispatch_interrupt(&new_frame);
        convert_to_fred(frame, &new_frame);
    }
}


void x86_64_fred_entry_ring0(fred_frame_t* frame) {
    interrupt_frame_t new_frame;
    convert_from_fred(&new_frame, frame);
    x86_64_dispatch_interrupt(&new_frame);
    convert_to_fred(frame, &new_frame);
}
