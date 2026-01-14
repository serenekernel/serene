#pragma once

#include <arch/interrupts.h>

typedef void (*fn_interrupt_handler)(interrupt_frame_t* frame);
extern fn_interrupt_handler interrupt_handlers[256];

void register_interrupt_handler(int vector, fn_interrupt_handler handler);
void unregister_interrupt_handler(int vector);
void enable_interrupts();
void disable_interrupts();
bool interrupts_enabled();

void setup_interrupts_bsp();
void setup_interrupts_ap();