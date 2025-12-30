#pragma once

#include <arch/interrupts.h>

typedef void (*fn_interrupt_handler)(interrupt_frame* frame);

void register_interrupt_handler(int vector, fn_interrupt_handler handler);
void unregister_interrupt_handler(int vector);
void enable_interrupts();
void disable_interrupts();
bool interrupts_enabled();
