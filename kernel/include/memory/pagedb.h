#include <lib/sparse_array.h>
#include <memory/vmm.h>
#include <stdint.h>

typedef struct {
    uint8_t demand     : 1;
    uint8_t __reserved : 7;
} page_db_entry_t;

page_db_entry_t* page_db_access(vm_allocator_t* allocator, virt_addr_t virt_addr);
page_db_entry_t* page_db_access_demand(vm_allocator_t* allocator, virt_addr_t virt_addr);
