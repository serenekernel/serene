#pragma once
#include <memory/memory.h>
#include <stdint.h>

typedef struct {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
} regs_t;

typedef struct {
    uint64_t vector, error, interrupt_data;
    regs_t* regs;
    bool is_user;
    void* internal_frame;
} interrupt_frame_t;

typedef struct {
    regs_t regs;
    uint64_t vector, error;
    uint64_t rip, cs, rflags, rsp, ss;
} idt_frame_t;

typedef struct fred_frame {
    regs_t regs;
    uint64_t error;
    uint64_t rip, cs, rflags, rsp, ss;
    uint64_t fred_event_data;
    uint64_t fred_reserved;
} fred_frame_t;


// Sets the stack to be used when being interrupted from ring 3

void x86_64_set_rsp0_stack(virt_addr_t stack);
bool x86_64_fred_enabled();
