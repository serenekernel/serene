#include <common/arch.h>
#include <common/requests.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdio.h>

const char* arch_get_name(void) {
    return "aarch64";
}


[[noreturn]] void arch_die(void) {
    for(;;) {
        __asm__ volatile("msr daifset, #0xf");
        __asm__ volatile("wfi");
    }
}

void arch_memory_barrier(void) {
    __asm__ volatile("dmb ish" ::: "memory");
}

void arch_pause() {
    __asm__ volatile("yield" ::: "memory");
}

void arch_init_bsp() {
    pmm_init();
    printf("pmm\n");

    phys_addr_t highest_phys_address = 0;
    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* entry = memmap_request.response->entries[i];
        if(entry->base + entry->length > highest_phys_address) {
            highest_phys_address = entry->base + entry->length;
        }
    }

    virt_addr_t virtual_start = (virt_addr_t) highest_phys_address + hhdm_request.response->offset;

    vmm_kernel_init(&kernel_allocator, virtual_start, virtual_start + 0x80000000);
    printf("vmm\n");
    vm_paging_bsp_init(&kernel_allocator);
    printf("paging\n");
    vm_map_kernel();
    printf("we pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("we didn't die\n");
}

void arch_init_ap() {
    vm_paging_ap_init(&kernel_allocator);
    printf("ap paging pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("ap didn't kill itself\n");
}
