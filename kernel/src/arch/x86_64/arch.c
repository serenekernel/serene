#include "arch/cpuid.h"
#include "arch/hardware/lapic.h"

#include <arch/gdt.h>
#include <arch/interrupts.h>
#include <common/arch.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdio.h>

const char* arch_get_name(void) {
    return "x86_64";
}

[[noreturn]] void arch_die(void) {
    for(;;) {
        __asm__ volatile("cli");
        __asm__ volatile("hlt");
    }
}

void arch_memory_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

void arch_pause() {
    __asm__ volatile("pause" ::: "memory");
}

void arch_init_bsp() {
    pmm_init();
    vmm_init(&kernel_allocator, 0xFFFF800000000000, 0xFFFF800040000000);
    vm_paging_bsp_init(&kernel_allocator);

    vm_map_kernel();
    printf("we pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("we didn't die\n");

    setup_gdt();
    printf("GDT INIT OK!\n");
    lapic_init_bsp();
    printf("LAPIC INIT OK!\n");
    setup_idt_bsp();
    // We're done, just hang...
}

void arch_init_ap() {
    vm_paging_ap_init(&kernel_allocator);
    printf("ap paging pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("ap didn't kill itself\n");

    setup_gdt();
    setup_idt_ap();
}

uint32_t arch_get_core_id() {
    return lapic_get_id();
}

bool arch_is_bsp() {
    return lapic_is_bsp();
}
