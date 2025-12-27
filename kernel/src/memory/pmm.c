#include "arch/memory.h"

#include <common/memory.h>
#include <common/requests.h>
#include <limine.h>
#include <memory/pmm.h>
#include <stddef.h>
#include <stdio.h>

typedef struct pmm_node {
    struct pmm_node* next;
} pmm_node_t;


pmm_node_t* head = NULL;

phys_addr_t pmm_alloc_page() {
    pmm_node_t* current = head;
    if(current == NULL) { return 0; }
    head = head->next;
    return (phys_addr_t) current - hhdm_request.response->offset;
}

void pmm_free_page(phys_addr_t addr) {
    pmm_node_t* node = (pmm_node_t*) (addr + hhdm_request.response->offset);
    node->next = head;
    head = node;
}

void pmm_init() {
    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* entry = memmap_request.response->entries[i];

        printf("%s, 0x%016lx - 0x%016lx (%zu)\n", limine_memmap_type_to_str(entry->type), entry->base, entry->base + entry->length, entry->length);

        if(entry->type == LIMINE_MEMMAP_USABLE) {
            phys_addr_t start = ALIGN_UP(entry->base, PAGE_SIZE_DEFAULT);
            phys_addr_t end = ALIGN_DOWN(entry->base + entry->length, PAGE_SIZE_DEFAULT);

            for(phys_addr_t addr = start; addr < end; addr += PAGE_SIZE_DEFAULT) { pmm_free_page(addr); }
        }
    }
}
