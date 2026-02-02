#include <common/requests.h>
#include <common/spinlock.h>
#include <memory/memobj.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdio.h>
#include <string.h>

static uint64_t next_memobj_id = 1;
static memobj_t* memobj_list_head = NULL;
static spinlock_t memobj_lock = 0;

void memobj_init(void) {
    memobj_list_head = NULL;
    next_memobj_id = 1;
}

memobj_t* memobj_create(size_t size, memobj_perms_t perms) {
    if(size == 0) {
        return NULL;
    }

    size_t aligned_size = ALIGN_UP(size, PAGE_SIZE_DEFAULT);
    size_t page_count = aligned_size / PAGE_SIZE_DEFAULT;

    memobj_t* memobj = (memobj_t*) vmm_alloc_object(&kernel_allocator, sizeof(memobj_t));

    if(!memobj) {
        printf("Failed to allocate memobj structure\n");
        return NULL;
    }

    size_t pages_array_size = page_count * sizeof(phys_addr_t);
    memobj->physical_pages = (phys_addr_t*) vmm_alloc_object(&kernel_allocator, pages_array_size);

    if(!memobj->physical_pages) {
        printf("Failed to allocate physical pages array\n");
        vmm_free(&kernel_allocator, (virt_addr_t) memobj);
        return NULL;
    }

    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t page = pmm_alloc_page();
        if(page == 0) {
            printf("Failed to allocate physical page %zu/%zu\n", i, page_count);
            for(size_t j = 0; j < i; j++) {
                pmm_free_page(memobj->physical_pages[j]);
            }
            vmm_free(&kernel_allocator, (virt_addr_t) memobj->physical_pages);
            vmm_free(&kernel_allocator, (virt_addr_t) memobj);
            return NULL;
        }
        memobj->physical_pages[i] = page;
    }

    for(size_t i = 0; i < page_count; i++) {
        virt_addr_t virt = TO_HHDM(memobj->physical_pages[i]);
        memset((void*) virt, 0, PAGE_SIZE_DEFAULT);
    }

    uint64_t __spinflags = spinlock_critical_lock(&memobj_lock);
    memobj->id = next_memobj_id++;
    memobj->size = aligned_size;
    memobj->page_count = page_count;
    memobj->max_perms = perms;
    memobj->ref_count = 1;
    memobj->zero_filled = true;

    // Add to global list
    memobj->global_next = memobj_list_head;
    memobj->global_prev = NULL;
    if(memobj_list_head) {
        memobj_list_head->global_prev = memobj;
    }
    memobj_list_head = memobj;

    spinlock_critical_unlock(&memobj_lock, __spinflags);

    printf("Created memobj id=%llu size=%zu pages=%zu perms=0x%x\n", memobj->id, memobj->size, memobj->page_count, memobj->max_perms);

    return memobj;
}

void memobj_destroy(memobj_t* memobj) {
    if(!memobj) {
        return;
    }

    uint64_t __spinflags = spinlock_critical_lock(&memobj_lock);

    memobj->ref_count--;

    if(memobj->ref_count > 0) {
        spinlock_critical_unlock(&memobj_lock, __spinflags);
        return;
    }

    if(memobj->global_prev) {
        memobj->global_prev->global_next = memobj->global_next;
    } else {
        memobj_list_head = memobj->global_next;
    }
    if(memobj->global_next) {
        memobj->global_next->global_prev = memobj->global_prev;
    }

    spinlock_critical_unlock(&memobj_lock, __spinflags);

    printf("Destroying memobj id=%llu\n", memobj->id);

    for(size_t i = 0; i < memobj->page_count; i++) {
        pmm_free_page(memobj->physical_pages[i]);
    }

    vmm_free(&kernel_allocator, (virt_addr_t) memobj->physical_pages);
    vmm_free(&kernel_allocator, (virt_addr_t) memobj);
}

void memobj_ref(memobj_t* memobj) {
    if(!memobj) {
        return;
    }

    uint64_t __spinflags = spinlock_critical_lock(&memobj_lock);
    memobj->ref_count++;
    spinlock_critical_unlock(&memobj_lock, __spinflags);
}

void memobj_unref(memobj_t* memobj) {
    memobj_destroy(memobj);
}

vm_flags_t memobj_perms_to_vm_flags(memobj_perms_t perms) {
    vm_flags_t flags = 0;

    if(perms & MEMOBJ_PERM_WRITE) {
        flags |= VM_READ_WRITE;
    } else {
        flags |= VM_READ_ONLY;
    }

    if(perms & MEMOBJ_PERM_EXEC) {
        flags |= VM_EXECUTE;
    }

    return flags;
}

bool memobj_validate_perms(memobj_perms_t requested, memobj_perms_t maximum) {
    return (requested & maximum) == requested;
}

virt_addr_t memobj_map(vm_allocator_t* allocator, memobj_t* memobj, virt_addr_t vaddr, memobj_perms_t perms, memobj_map_flags_t flags) {
    if(!allocator || !memobj) {
        printf("memobj_map: invalid parameters\n");
        return 0;
    }

    if(!memobj_validate_perms(perms, memobj->max_perms)) {
        printf("memobj_map: requested permissions 0x%x exceed maximum 0x%x\n", perms, memobj->max_perms);
        return 0;
    }

    vm_node_t* node = NULL;

    if(vaddr == 0) {
        node = vmm_alloc_raw(allocator, memobj->page_count);
        if(node == 0) {
            printf("memobj_map: failed to allocate virtual address space\n");
            return 0;
        }
        vaddr = node->base;
    } else if(flags & MEMOBJ_MAP_FIXED) {
        virt_addr_t result = vmm_try_alloc_backed(allocator, vaddr, memobj->page_count, VM_ACCESS_USER, VM_CACHE_NORMAL, memobj_perms_to_vm_flags(perms), false);
        if(result == 0) {
            printf("memobj_map: failed to allocate at fixed address 0x%llx\n", vaddr);
            return 0;
        }
        vaddr = result;

        rb_node_t* rb = rb_find_exact(&allocator->vm_tree, vaddr);
        node = (vm_node_t*) rb;
    } else {
        node = vmm_alloc_raw(allocator, memobj->page_count);
        if(!node) {
            printf("memobj_map: failed to allocate virtual address space\n");
            return 0;
        }
        vaddr = node->base;
    }

    if(node) {
        node->options_type = VM_OPTIONS_MEMOBJ;
        node->options.memobj.memobj = memobj;
    }

    vm_flags_t vm_flags = memobj_perms_to_vm_flags(perms);

    for(size_t i = 0; i < memobj->page_count; i++) {
        virt_addr_t page_vaddr = vaddr + (i * PAGE_SIZE_DEFAULT);
        phys_addr_t page_paddr = memobj->physical_pages[i];

        vm_map_page(allocator, page_vaddr, page_paddr, VM_ACCESS_USER, VM_CACHE_NORMAL, vm_flags);
    }

    memobj_ref(memobj);

    printf("Mapped memobj id=%llu to vaddr=0x%llx size=%zu perms=0x%x\n", memobj->id, vaddr, memobj->size, perms);

    return vaddr;
}

bool memobj_unmap(vm_allocator_t* allocator, virt_addr_t vaddr) {
    if(!allocator || vaddr == 0) {
        return false;
    }

    vm_unmap_page(allocator, vaddr);

    return true;
}

memobj_t* memobj_get_by_id(uint64_t id) {
    uint64_t __spinflags = spinlock_critical_lock(&memobj_lock);

    memobj_t* current = memobj_list_head;
    while(current) {
        if(current->id == id) {
            spinlock_critical_unlock(&memobj_lock, __spinflags);
            return current;
        }
        current = current->global_next;
    }

    spinlock_critical_unlock(&memobj_lock, __spinflags);
    return NULL;
}
