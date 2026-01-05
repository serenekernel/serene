#include "common/memory.h"
#include "memory/pmm.h"
#include "rbtree.h"
#include "sparse_array.h"

#include <common/requests.h>
#include <memory/pagedb.h>
#include <memory/vmm.h>

vm_allocator_t kernel_allocator;

size_t vm_value_of_node(rb_node_t* node) {
    vm_node_t* vm_node = (vm_node_t*) node;
    return vm_node->base;
}

size_t vm_length_of_node(rb_node_t* node) {
    vm_node_t* vm_node = (vm_node_t*) node;
    return vm_node->size;
}

void vmm_kernel_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end) {
    allocator->start = start;
    allocator->end = end;
    allocator->vm_tree.root = nullptr;
#ifdef __ARCH_AARCH64__
    allocator->paging_structures_base = 0;
#endif
    allocator->kernel_paging_structures_base = 0;
    allocator->vm_tree.value_of_node = vm_value_of_node;
    allocator->vm_tree.length_of_node = vm_length_of_node;
}

void vmm_user_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end) {
    allocator->start = start;
    allocator->end = end;
    allocator->vm_tree.root = nullptr;
#ifdef __ARCH_AARCH64__
    allocator->paging_structures_base = 0;
#endif
    allocator->kernel_paging_structures_base = 0;
    allocator->vm_tree.value_of_node = vm_value_of_node;
    allocator->vm_tree.length_of_node = vm_length_of_node;
}

vm_node_t* vmm_alloc_raw(vm_allocator_t* allocator, size_t page_count) {
    size_t total_size = page_count * PAGE_SIZE_DEFAULT;

    virt_addr_t alloc_addr = rb_find_first_gap(&allocator->vm_tree, allocator->start, allocator->end, total_size);
    if(alloc_addr == 0) {
        return 0;
    }

    phys_addr_t node_phys = pmm_alloc_page();
    if(node_phys == 0) {
        return 0;
    }

    vm_node_t* new_node = (vm_node_t*) (node_phys + hhdm_request.response->offset);
    new_node->base = alloc_addr;
    new_node->size = total_size;

    rb_insert(&allocator->vm_tree, &new_node->rb_node);

    return new_node;
}

virt_addr_t vmm_alloc(vm_allocator_t* allocator, size_t page_count) {
    vm_node_t* node = vmm_alloc_raw(allocator, page_count);
    node->options_type = VM_OPTIONS_NONE;
    return node->base;
}

virt_addr_t vmm_alloc_demand(vm_allocator_t* allocator, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags) {
    vm_node_t* node = vmm_alloc_raw(allocator, page_count);
    node->options_type = VM_OPTIONS_DEMAND;
    node->options.demand.flags = flags;
    node->options.demand.access = access;
    node->options.demand.cache = cache;
    return node->base;
}

void vmm_free(vm_allocator_t* allocator, virt_addr_t addr) {
    rb_node_t* node = rb_find_exact(&allocator->vm_tree, addr);
    if(node) {
        rb_remove(&allocator->vm_tree, node);
        vm_node_t* vm_node = (vm_node_t*) node;
        pmm_free_page((phys_addr_t) vm_node - hhdm_request.response->offset);
    }
}

void vm_map_kernel() {
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

    // @todo: parse the kernel binary CORRECTLY
    vm_map_pages_continuous(&kernel_allocator, kernel_mapping.response->virtual_base, kernel_mapping.response->physical_base, kernel_page_count, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE | VM_EXECUTE);

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
            vm_map_pages_continuous(&kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE);
        } else if(current->type == LIMINE_MEMMAP_FRAMEBUFFER) {
            vm_map_pages_continuous(&kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_WRITE_COMBINE, VM_READ_WRITE);
        } else if(current->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE || current->type == LIMINE_MEMMAP_ACPI_TABLES) {
            vm_map_pages_continuous(&kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_WRITE_THROUGH, VM_READ_WRITE);
        }
    }
}
