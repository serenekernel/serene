#pragma once
#include <common/interrupts.h>

void arch_init_bsp();
void arch_init_ap();

const char* arch_get_name(void);
[[noreturn]] void arch_die(void);
void arch_memory_barrier(void);
void arch_pause();

void arch_panic_int(interrupt_frame* frame);
