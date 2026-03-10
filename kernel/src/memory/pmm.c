#include "common/spinlock.h"

#include <assert.h>
#include <common/requests.h>
#include <memory/memory.h>
#include <memory/pmm.h>
#include <stddef.h>
#include <stdio.h>

typedef struct pmm_node {
    struct pmm_node* next;
} pmm_node_t;

pmm_node_t* head = NULL;
spinlock_t pmm_lock = SPINLOCK_INIT;
phys_addr_t pmm_alloc_page() {
    spinlock_lock(&pmm_lock);
    pmm_node_t* current = head;
    assert(current != NULL && "out of physical memory");
    head = head->next;
    spinlock_unlock(&pmm_lock);
    return (phys_addr_t) FROM_HHDM(current);
}

void pmm_free_page(phys_addr_t addr) {
    pmm_node_t* node = (pmm_node_t*) TO_HHDM(addr);
    spinlock_lock(&pmm_lock);
    node->next = head;
    head = node;
    spinlock_unlock(&pmm_lock);
}

void pmm_init() {
    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* entry = memmap_request.response->entries[i];

        printf("%s, 0x%016lx - 0x%016lx (%zu)\n", limine_memmap_type_to_str(entry->type), entry->base, entry->base + entry->length, entry->length);

        if(entry->type == LIMINE_MEMMAP_USABLE) {
            phys_addr_t start = ALIGN_UP(entry->base, PAGE_SIZE_DEFAULT);
            phys_addr_t end = ALIGN_DOWN(entry->base + entry->length, PAGE_SIZE_DEFAULT);

            for(phys_addr_t addr = start; addr < end; addr += PAGE_SIZE_DEFAULT) {
                pmm_node_t* node = (pmm_node_t*) TO_HHDM(addr);
                node->next = head;
                head = node;
            }
        }
    }
}
