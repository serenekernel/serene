#include <lib/sparse_array.h>
#include <memory/pagedb.h>
#include <memory/vmm.h>

page_db_entry_t* page_db_access(vm_allocator_t* allocator, virt_addr_t virt_addr) {
    size_t page_index = (virt_addr - allocator->start) / PAGE_SIZE_DEFAULT;
    return (page_db_entry_t*) sparse_array_access(allocator->page_db, page_index);
}

page_db_entry_t* page_db_access_demand(vm_allocator_t* allocator, virt_addr_t virt_addr) {
    size_t page_index = (virt_addr - allocator->start) / PAGE_SIZE_DEFAULT;
    return (page_db_entry_t*) sparse_array_access_demand(allocator->page_db, page_index);
}
