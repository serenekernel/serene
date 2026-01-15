#pragma once
#include <common/interrupts.h>
#include <stddef.h>
#include <limine.h>

void arch_init_bsp();
void arch_init_ap(struct limine_mp_info* info);

const char* arch_get_name(void);
[[noreturn]] void arch_die(void);
void arch_wait_for_interrupt(void);
void arch_memory_barrier(void);
void arch_pause();

void arch_panic_int(interrupt_frame_t* frame);

uint64_t arch_get_flags();
void arch_set_flags(uint64_t flags);

uint32_t arch_get_core_id();
bool arch_is_bsp();

size_t arch_get_max_cpu_id(void);
void arch_debug_putc(char c);