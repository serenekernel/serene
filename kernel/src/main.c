#include "common/memory.h"
#include "memory/vmm.h"

#include <common/arch.h>
#include <common/memory.h>
#include <common/requests.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>
#include <limine.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdio.h>

void setup_paging(vm_allocator_t* kernel_allocator) {
    extern uint64_t kernel_start;
    extern uint64_t kernel_end;

    virt_addr_t start = ALIGN_DOWN((virt_addr_t) &kernel_start, 4096);
    virt_addr_t end = ALIGN_UP((virt_addr_t) &kernel_end, 4096);

    size_t kernel_page_count = ALIGN_UP((end - start), PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;
    // kernel_mapping->virtual_base is the source virtual base (where kernel is currently linked),
    // kernel_mapping->physical_base is the corresponding physical base. we map target virtual
    // addresses (the kernel's higher-half addresses) to the physical frames.
    printf("kernel_mapping.response->virtual_base=%p\n", kernel_mapping.response->virtual_base);
    printf("kernel_mapping.response->physical_base=%p\n", kernel_mapping.response->physical_base);
    printf("&kernel_start=%p &kernel_end=%p, kernel_page_count=%lu\n", &kernel_start, &kernel_end, kernel_page_count);

    vm_map_pages_continuous(kernel_allocator, kernel_mapping.response->virtual_base, kernel_mapping.response->physical_base, kernel_page_count, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE_EXECUTE));
}

void setup_rest_paging(vm_allocator_t* kernel_allocator) {
    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* current = memmap_request.response->entries[i];

        phys_addr_t phys_base = ALIGN_DOWN(current->base, 4096);
        virt_addr_t virt_base = phys_base + hhdm_request.response->offset;
        size_t page_count = ALIGN_UP(current->length, 4096) / 4096;

        printf("0x%016llx -> 0x%016llx (0x%08llx | %s)", phys_base, virt_base, current->length, limine_memmap_type_to_str(current->type));
        if(current->type == LIMINE_MEMMAP_USABLE || current->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE || current->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES || current->type == LIMINE_MEMMAP_FRAMEBUFFER ||
           current->type == LIMINE_MEMMAP_ACPI_TABLES || current->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE)
        {
            printf(" will be mapped\n");
        } else {
            printf(" will not be mapped\n");
        }

        if(current->type == LIMINE_MEMMAP_USABLE || current->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE || current->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES) {
            vm_map_pages_continuous(kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
        } else if(current->type == LIMINE_MEMMAP_FRAMEBUFFER) {
            vm_map_pages_continuous(kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_WRITE_COMBINE, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
        } else if(current->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE || current->type == LIMINE_MEMMAP_ACPI_TABLES) {
            vm_map_pages_continuous(kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_WRITE_THROUGH, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
        }
    }
}

void kmain(void) {
    verify_requests();
    term_init();

    printf("Hello, %s!\n", arch_get_name());
    pmm_init();
    vm_allocator_t allocator;
    vmm_init(&allocator, 0xFFFF800000000000, 0xFFFF800040000000);
    vm_paging_bsp_init(&allocator);

    printf("1\n");
    setup_paging(&allocator);
    printf("2\n");
    setup_rest_paging(&allocator);
    printf("we pray\n");
    vm_address_space_switch(&allocator);
    printf("we didn't die\n");
    virt_addr_t addr1 = vmm_alloc(&allocator, 1);
    virt_addr_t addr2 = vmm_alloc(&allocator, 1);

    phys_addr_t phys1 = pmm_alloc_page();

    vm_map_page(&allocator, addr1, phys1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, (vm_protection_flags_t) { .present = true, .readable = true, .write = true, .execute = false });
    vm_map_page(&allocator, addr2, phys1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, (vm_protection_flags_t) { .present = true, .readable = true, .write = true, .execute = false });

    *((uint64_t*) addr1) = 0x123456789ABCDEF0;
    printf("Value at addr1: 0x%016lx\n", *((uint64_t*) addr1));
    printf("Value at addr2: 0x%016lx\n", *((uint64_t*) addr2));


    // We're done, just hang...
    arch_die();
}
