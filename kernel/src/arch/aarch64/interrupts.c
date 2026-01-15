#include <arch/interrupts.h>
#include <common/interrupts.h>
#include <assert.h>

fn_interrupt_handler interrupt_handlers[256] = { 0 };

void register_interrupt_handler(int vector, fn_interrupt_handler handler) {
    // @todo:
    (void)vector;
    (void)handler;
    assert(false && "unimplemented");
}

void unregister_interrupt_handler(int vector) {
    // @todo:
    (void)vector;
    assert(false && "unimplemented");
}

void setup_interrupts_bsp() {
    // @todo: 
    assert(false && "unimplemented");
}

void setup_interrupts_ap() {
    // @todo: 
    assert(false && "unimplemented");
}

void enable_interrupts() {
    // @todo: 
    assert(false && "unimplemented");
}

void disable_interrupts() {
    // @todo: 
    assert(false && "unimplemented");
}

bool interrupts_enabled() {
    // @todo: 
    assert(false && "unimplemented");
    return false;
}
