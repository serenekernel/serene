#pragma once
#include <memory/memory.h>
#include <lib/sparse_array.h>
#include <rbtree.h>
#include <stddef.h>

typedef enum {
    VM_OPTIONS_NONE = 0,
    VM_OPTIONS_DEMAND,
    VM_OPTIONS_BACKED
} vm_node_options_t;

typedef struct {
    rb_node_t rb_node;
    uintptr_t base;
    size_t size;

    vm_node_options_t options_type;
    union {
        struct {
            vm_cache_t cache;
            vm_access_t access;
            vm_flags_t flags;
            bool zero_fill;
        } demand;
    } options;

} vm_node_t;

typedef struct {
    bool is_user;
    virt_addr_t start;
    virt_addr_t end;

#ifdef __ARCH_AARCH64__
    // for the ttbr0_el1
    phys_addr_t paging_structures_base;
#endif
    // for the ttbr1_el1 or cr3 on x86
    phys_addr_t kernel_paging_structures_base;

    rb_tree_t vm_tree;
} vm_allocator_t;

extern vm_allocator_t kernel_allocator;

void vmm_kernel_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end);
void vmm_user_init(vm_allocator_t* allocator, virt_addr_t start, virt_addr_t end);

void vmm_destory_allocator(vm_allocator_t* allocator);

virt_addr_t vmm_alloc(vm_allocator_t* allocator, size_t page_count);
virt_addr_t vmm_alloc_demand(vm_allocator_t* allocator, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags);
virt_addr_t vmm_alloc_backed(vm_allocator_t* allocator, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags, bool zero_fill);
virt_addr_t vmm_try_alloc_backed(vm_allocator_t* allocator, virt_addr_t address, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags, bool zero_fill);
virt_addr_t vmm_alloc_object(vm_allocator_t* allocator, size_t object_size);

virt_addr_t vmm_copy_read_only(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t size);

void vmm_free(vm_allocator_t* allocator, virt_addr_t addr);

void vm_map_page(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, vm_access_t access, vm_cache_t cache, vm_flags_t flags);
void vm_reprotect_page(vm_allocator_t* allocator, virt_addr_t virt_addr, vm_access_t access, vm_cache_t cache, vm_flags_t flags);
void vm_remap_page(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t new_phys_addr);
phys_addr_t vm_resolve(vm_allocator_t* allocator, virt_addr_t virt_addr);
void vm_unmap_page(vm_allocator_t* allocator, virt_addr_t virt_addr);

void vm_map_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags);
void vm_unmap_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, size_t page_count);

void vm_flush_page_raw(virt_addr_t addr);
void vm_flush_page_dispatch(virt_addr_t addr);

void vm_paging_bsp_init(vm_allocator_t* allocator);
void vm_paging_ap_init(vm_allocator_t* allocator);

void vm_address_space_switch(vm_allocator_t* allocator);
phys_addr_t vm_address_space_switch_raw(phys_addr_t cr3);

void vm_map_kernel();

typedef enum {
    VM_FAULT_UKKNOWN = 0,
    VM_FAULT_NOT_PRESENT,
} vm_fault_reason_t;

bool vm_handle_page_fault(vm_fault_reason_t reason, virt_addr_t fault_address);
