#include <limine.h>
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

    virt_addr_t virtual_start = (virt_addr_t) TO_HHDM(highest_phys_address);

    vmm_kernel_init(&kernel_allocator, virtual_start, virtual_start + 0x80000000);
    printf("vmm\n");
    vm_paging_bsp_init(&kernel_allocator);
    printf("paging\n");
    vm_map_kernel();
    printf("we pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("we didn't die\n");
}

void arch_init_ap(struct limine_mp_info* info) {
    (void)info;
    vm_paging_ap_init(&kernel_allocator);
    printf("ap paging pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("ap didn't kill itself\n");
}

void arch_wait_for_interrupt(void) {
    __asm__ volatile("wfi");
}

uint32_t arch_get_core_id() {
    // @todo: implement proper core id
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return (uint32_t)(mpidr & 0xFF);
}

bool arch_is_bsp() {
    // @todo: implement proper bsp detection
    return arch_get_core_id() == 0;
}

uint64_t arch_get_flags() {
    // @todo: implement proper flags reading
    uint64_t daif;
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    return daif;
}

void arch_set_flags(uint64_t flags) {
    // @todo: implement proper flags setting
    __asm__ volatile("msr daif, %0" : : "r"(flags));
}

size_t arch_get_max_cpu_id(void) {
    // @todo: implement proper max CPU ID detection
    size_t highest_id = 0;
    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        uint32_t mpidr = mp_request.response->cpus[i]->mpidr;
        uint32_t core_id = mpidr & 0xFF;
        if(core_id > highest_id) {
            highest_id = core_id;
        }
    }
    return highest_id;
}

// Architecture-specific IPI implementations (stubs)
void arch_ipi_send_raw(uint32_t cpu_id, uint8_t vector) {
    // @todo: 
    (void)cpu_id;
    (void)vector;
}

void arch_ipi_broadcast_raw(uint8_t vector) {
    // @todo: 
    (void)vector;
}

void arch_ipi_eoi(void) {
}

void arch_panic_int(interrupt_frame_t* frame) {
    // @todo: 
    (void)frame;
    printf("panic: unhandled interrupt on aarch64\n");
    arch_die();
}

void arch_debug_putc(char c) {
    // @todo:
    (void)c;
}
