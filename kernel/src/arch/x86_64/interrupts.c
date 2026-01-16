#include <common/interrupts.h>
#include <stdint.h>
#include <assert.h>

fn_interrupt_handler interrupt_handlers[256] = { 0 };

void register_interrupt_handler(int vector, fn_interrupt_handler handler) {
    assert(vector >= 0 && vector < 256);
    assert(interrupt_handlers[vector] == 0 && "Interrupt handler already registered for this vector");
    interrupt_handlers[vector] = handler;
}

void unregister_interrupt_handler(int vector) {
    assert(vector >= 0 && vector < 256);
    assert(interrupt_handlers[vector] != 0 && "No interrupt handler registered for this vector");
    interrupt_handlers[vector] = 0;
}

void enable_interrupts() {
    asm volatile("sti");
}

void disable_interrupts() {
    asm volatile("cli");
}

bool interrupts_enabled() {
    uint64_t rflags;
    asm volatile("pushfq\n" "popq %0\n" : "=r"(rflags));
    return (rflags & (1 << 9)) != 0;
}
