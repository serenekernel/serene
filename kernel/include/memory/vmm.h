#pragma once
#include <common/memory.h>
#include <rbtree.h>
#include <stddef.h>

typedef struct {
    virt_addr_t start;
    virt_addr_t end;
    rb_tree_t vm_tree;
} vm_allocator_t;

void vmm_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end);
virt_addr_t vmm_alloc(vm_allocator_t* allocator, size_t page_count);
void vmm_free(vm_allocator_t* allocator, virt_addr_t addr);
