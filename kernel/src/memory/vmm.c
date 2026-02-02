#include "common/arch.h"
#include "memory/memobj.h"
#include "memory/memory.h"
#include "memory/pmm.h"
#include "rbtree.h"
#include "sparse_array.h"

#include <assert.h>
#include <common/requests.h>
#include <memory/pagedb.h>
#include <memory/vmm.h>
#include <string.h>

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
    allocator->is_user = false;
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

void vm_paging_setup_user(vm_allocator_t* allocator);

void vmm_user_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end) {
    allocator->is_user = true;
    allocator->start = start;
    allocator->end = end;
    allocator->vm_tree.root = nullptr;
#ifdef __ARCH_AARCH64__
    allocator->paging_structures_base = 0;
#endif
    allocator->kernel_paging_structures_base = 0;
    allocator->vm_tree.value_of_node = vm_value_of_node;
    allocator->vm_tree.length_of_node = vm_length_of_node;
    vm_paging_setup_user(allocator);
}

void vmm_destory_allocator(vm_allocator_t* allocator) {
    while(true) {
        rb_node_t* node = rb_find_first(&allocator->vm_tree);
        if(node == nullptr) {
            break;
        }
        vmm_free(allocator, ((vm_node_t*) node)->base);
    }
}

vm_node_t* vmm_alloc_raw(vm_allocator_t* allocator, size_t page_count) {
    size_t total_size = page_count * PAGE_SIZE_DEFAULT;
    virt_addr_t alloc_addr = rb_find_first_gap(&allocator->vm_tree, allocator->start, allocator->end, total_size);
    phys_addr_t node_phys = pmm_alloc_page();
    assert(alloc_addr != 0 && "vmm_alloc_raw: no suitable virtual address range found");
    assert(node_phys != 0 && "vmm_alloc_raw: failed to allocate memory for vm_node");

    vm_node_t* new_node = (vm_node_t*) (TO_HHDM(node_phys));
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
    node->options.demand.zero_fill = true;
    return node->base;
}

virt_addr_t vmm_alloc_backed(vm_allocator_t* allocator, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags, bool zero_fill) {
    vm_node_t* node = vmm_alloc_raw(allocator, page_count);
    assert(node != nullptr && "vmm_alloc_backed: failed to allocate vm_node");
    assert(page_count > 0 && "vmm_alloc_backed: page_count must be greater than 0");
    assert((flags & VM_NON_PRESENT) == 0 && "vmm_alloc_backed: cannot allocate backed memory with VM_NON_PRESENT flag");

    node->options_type = VM_OPTIONS_BACKED;
    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t phys = pmm_alloc_page();
        if(zero_fill) {
            memset((void*) TO_HHDM(phys), 0, PAGE_SIZE_DEFAULT);
        }
        vm_map_page(allocator, node->base + (i * PAGE_SIZE_DEFAULT), phys, access, cache, flags);
    }

    return node->base;
}

virt_addr_t vmm_try_alloc_backed(vm_allocator_t* allocator, virt_addr_t address, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags, bool zero_fill) {
    size_t total_size = page_count * PAGE_SIZE_DEFAULT;

    rb_node_t* existing_node = rb_find_exact(&allocator->vm_tree, address);
    if(existing_node != nullptr) {
        return 0;
    }

    // Check for overlaps
    rb_node_t* lower_node = rb_find_lower(&allocator->vm_tree, address);
    if(lower_node != nullptr) {
        vm_node_t* lower_vm_node = (vm_node_t*) lower_node;
        if(lower_vm_node->base + lower_vm_node->size > address) {
            return 0;
        }
    }

    rb_node_t* upper_node = rb_find_upper(&allocator->vm_tree, address);
    if(upper_node != nullptr) {
        vm_node_t* upper_vm_node = (vm_node_t*) upper_node;
        if(address + total_size > upper_vm_node->base) {
            return 0;
        }
    }

    phys_addr_t node_phys = pmm_alloc_page();
    if(node_phys == 0) {
        return 0;
    }

    vm_node_t* new_node = (vm_node_t*) (TO_HHDM(node_phys));
    new_node->base = address;
    new_node->size = total_size;
    new_node->options_type = VM_OPTIONS_BACKED;

    rb_insert(&allocator->vm_tree, &new_node->rb_node);

    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t phys = pmm_alloc_page();
        if(zero_fill) {
            memset((void*) TO_HHDM(phys), 0, PAGE_SIZE_DEFAULT);
        }
        vm_map_page(allocator, new_node->base + (i * PAGE_SIZE_DEFAULT), phys, access, cache, flags);
    }

    return new_node->base;
}

virt_addr_t vmm_alloc_object(vm_allocator_t* allocator, size_t object_size) {
    size_t page_count = ALIGN_UP(object_size, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;
    vm_access_t access = allocator->is_user ? VM_ACCESS_USER : VM_ACCESS_KERNEL;
    return vmm_alloc_backed(allocator, page_count, access, VM_CACHE_NORMAL, VM_READ_WRITE, true);
}

// @note: this allows source pages to be changed after copying
// that's on the caller to ensure that doesn't happen :P
virt_addr_t vmm_copy_read_only(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t size) {
    size_t page_count = ALIGN_UP(size, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;

    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t src_phys = vm_resolve(src_alloc, src + (i * PAGE_SIZE_DEFAULT));
        assert(src_phys != 0 && "vmm_copy_read_only: source address not mapped");
        vm_map_page(dest_alloc, dest + (i * PAGE_SIZE_DEFAULT), src_phys, dest_alloc->is_user ? VM_ACCESS_USER : VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_ONLY);
    }

    return dest;
}

void vmm_free(vm_allocator_t* allocator, virt_addr_t addr) {
    bool irq = interrupts_enabled();
    rb_node_t* node = rb_find_exact(&allocator->vm_tree, addr);
    if(node) {
        rb_remove(&allocator->vm_tree, node);
        vm_node_t* vm_node = (vm_node_t*) node;

        if(vm_node->options_type == VM_OPTIONS_BACKED || vm_node->options_type == VM_OPTIONS_DEMAND) {
            size_t page_count = vm_node->size / PAGE_SIZE_DEFAULT;
            // Enable interrupts during unmap to allow IPI processing
            if(!irq) enable_interrupts();
            for(size_t i = 0; i < page_count; i++) {
                phys_addr_t phys = vm_resolve(allocator, vm_node->base + (i * PAGE_SIZE_DEFAULT));
                if(phys == 0) {
                    continue;
                }
                vm_unmap_page(allocator, vm_node->base + (i * PAGE_SIZE_DEFAULT));
                pmm_free_page(phys);
            }
            if(!irq) disable_interrupts();
        } else if(vm_node->options_type == VM_OPTIONS_MEMOBJ) {
            // for memobj mappings unmap pages but don't free physical memory
            // the memobj owns the physical pages
            size_t page_count = vm_node->size / PAGE_SIZE_DEFAULT;
            // Enable interrupts during unmap to allow IPI processing
            if(!irq) enable_interrupts();
            for(size_t i = 0; i < page_count; i++) {
                vm_unmap_page(allocator, vm_node->base + (i * PAGE_SIZE_DEFAULT));
            }
            if(!irq) disable_interrupts();

            memobj_t* memobj = vm_node->options.memobj.memobj;
            if(memobj) {
                memobj_unref(memobj);
            }
        }

        pmm_free_page((phys_addr_t) FROM_HHDM(vm_node));
    }
}

#define MAP_SEGMENT(name, map_type)                                                                                        \
    {                                                                                                                      \
        extern char name##_start[];                                                                                        \
        extern char name##_end[];                                                                                          \
        uintptr_t offset = name##_start - kernel_start;                                                                    \
        uintptr_t size = name##_end - name##_start;                                                                        \
        printf("%s - 0x%llx, 0x%llx\n", #name, offset, size);                                                              \
        for(uintptr_t i = offset; i < offset + size; i += PAGE_SIZE_DEFAULT) {                                             \
            vm_map_page(&kernel_allocator, kernel_virt + i, kernel_phys + i, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, map_type); \
        }                                                                                                                  \
    }

void vm_map_kernel() {
    extern char kernel_start[];
    phys_addr_t kernel_phys = (phys_addr_t) kernel_mapping.response->physical_base;
    virt_addr_t kernel_virt = (virt_addr_t) kernel_start;

    MAP_SEGMENT(text, VM_READ_ONLY | VM_EXECUTE);
    MAP_SEGMENT(rodata, VM_READ_ONLY);
    MAP_SEGMENT(data, VM_READ_WRITE);
    MAP_SEGMENT(requests, VM_READ_WRITE);

    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* current = memmap_request.response->entries[i];

        phys_addr_t phys_base = ALIGN_DOWN(current->base, 4096);
        virt_addr_t virt_base = FROM_HHDM(phys_base);
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
