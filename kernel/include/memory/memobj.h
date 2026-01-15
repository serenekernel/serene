#pragma once
#include <memory/memory.h>
#include <memory/vmm.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    MEMOBJ_PERM_READ = (1 << 0),
    MEMOBJ_PERM_WRITE = (1 << 1),
    MEMOBJ_PERM_EXEC = (1 << 2),
} memobj_perms_t;

typedef enum {
    MEMOBJ_MAP_FIXED = (1 << 0),
    MEMOBJ_MAP_GUARD = (1 << 1),
} memobj_map_flags_t;

typedef struct memobj {
    uint64_t id;
    size_t size;
    size_t page_count;
    memobj_perms_t max_perms;
    phys_addr_t* physical_pages;
    uint32_t ref_count;
    bool zero_filled;
    
    struct memobj* global_next;
    struct memobj* global_prev;
} memobj_t;

void memobj_init(void);

memobj_t* memobj_create(size_t size, memobj_perms_t max_perms);
void memobj_destroy(memobj_t* memobj);
void memobj_ref(memobj_t* memobj);
void memobj_unref(memobj_t* memobj);

// vaddr = 0 for automatic
virt_addr_t memobj_map(
    vm_allocator_t* allocator,
    memobj_t* memobj,
    virt_addr_t vaddr,
    memobj_perms_t perms,
    memobj_map_flags_t flags
);

bool memobj_unmap(vm_allocator_t* allocator, virt_addr_t vaddr);
vm_flags_t memobj_perms_to_vm_flags(memobj_perms_t perms);
bool memobj_validate_perms(memobj_perms_t requested, memobj_perms_t maximum);
memobj_t* memobj_get_by_id(uint64_t id);
