#include "common/memory.h"
#include "memory/pmm.h"
#include "rbtree.h"

#include <common/requests.h>
#include <memory/vmm.h>

typedef struct {
    rb_node_t rb_node;
    uintptr_t base;
    size_t size;
} vm_node_t;

size_t vm_value_of_node(rb_node_t* node) {
    vm_node_t* vm_node = (vm_node_t*) node;
    return vm_node->base;
}

size_t vm_length_of_node(rb_node_t* node) {
    vm_node_t* vm_node = (vm_node_t*) node;
    return vm_node->size;
}

void vmm_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end) {
    allocator->start = start;
    allocator->end = end;
    allocator->vm_tree.root = nullptr;
    allocator->vm_tree.value_of_node = vm_value_of_node;
    allocator->vm_tree.length_of_node = vm_length_of_node;
}

virt_addr_t vmm_alloc(vm_allocator_t* allocator, size_t page_count) {
    size_t total_size = page_count * DEFAULT_PAGE_SIZE;

    // Find first available gap using the rb_tree function
    virt_addr_t alloc_addr = rb_find_first_gap(&allocator->vm_tree, allocator->start, allocator->end, total_size);
    if(alloc_addr == 0) {
        return 0; // No suitable gap found
    }

    // Allocate physical memory for the vm_node_t structure
    phys_addr_t node_phys = pmm_alloc_page();
    if(node_phys == 0) {
        return 0; // Out of physical memory
    }

    // Convert physical address to virtual address using HHDM
    vm_node_t* new_node = (vm_node_t*) (node_phys + hhdm_request.response->offset);
    new_node->base = alloc_addr;
    new_node->size = total_size;

    // Insert into the red-black tree
    rb_insert(&allocator->vm_tree, &new_node->rb_node);

    return alloc_addr;
}

void vmm_free(vm_allocator_t* allocator, virt_addr_t addr) {
    rb_node_t* node = rb_find_exact(&allocator->vm_tree, addr);
    if(node) {
        rb_remove(&allocator->vm_tree, node);
        vm_node_t* vm_node = (vm_node_t*) node;
        pmm_free_page((phys_addr_t) vm_node - hhdm_request.response->offset);
    }
}
