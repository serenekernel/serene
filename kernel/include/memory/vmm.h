#pragma once
#include <common/memory.h>
#include <rbtree.h>
#include <stddef.h>

typedef struct {
    virt_addr_t start;
    virt_addr_t end;

    // @todo: I assume aarch64 uses phyiscal addresses for page tables
    // even then we can just kinda cast that way and ignore it being "physical"
    phys_addr_t paging_structures_base;

    rb_tree_t vm_tree;
} vm_allocator_t;

void vmm_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end);
virt_addr_t vmm_alloc(vm_allocator_t* allocator, size_t page_count);
void vmm_free(vm_allocator_t* allocator, virt_addr_t addr);

void vm_map_page(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, vm_access_t access, vm_cache_t cache, vm_protection_flags_t protection);
void vm_update_page(vm_allocator_t* allocator, virt_addr_t virt_addr, vm_access_t access, vm_cache_t cache, vm_protection_flags_t protection);
phys_addr_t vm_resolve(vm_allocator_t* allocator, virt_addr_t virt_addr);
void vm_unmap_page(vm_allocator_t* allocator, virt_addr_t virt_addr);

void vm_map_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, size_t page_count, vm_access_t access, vm_cache_t cache, vm_protection_flags_t protection);

void vm_flush_page_raw(virt_addr_t addr);
void vm_flush_page_dispatch(virt_addr_t addr);

void vm_paging_bsp_init(vm_allocator_t* allocator);
void vm_paging_ap_init(vm_allocator_t* allocator);

void vm_address_space_switch(vm_allocator_t* allocator);
