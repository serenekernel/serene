#pragma once
#include "arch/cr.h"
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

// Allows us to disable cr4.SMAP
bool arch_get_uap();
bool arch_disable_uap();
void arch_restore_uap(bool __prev);

// Allows us to disable cr0.WP
bool arch_get_wp();
bool arch_disable_wp();
void arch_restore_wp(bool __prev);

// Nice helper macros
#define ENTER_ADDRESS_SWITCH() \
    arch_memory_barrier(); \
    phys_addr_t __cr3_prev = __read_cr3(); \
    arch_memory_barrier();

#define EXIT_ADDRESS_SWITCH() \
    arch_memory_barrier(); \
    __write_cr3(__cr3_prev); \
    arch_memory_barrier();
    
#define ENTER_UAP_SECTION() \
    bool __uap_prev = arch_disable_uap();

#define EXIT_UAP_SECTION() \
    arch_restore_uap(__uap_prev);

#define ENTER_WP_SECTION() \
    bool __wp_prev = arch_disable_wp();

#define EXIT_WP_SECTION() \
    arch_restore_wp(__wp_prev);