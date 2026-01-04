#include "common/memory.h"
#include "memory/pmm.h"
#include "memory/vmm.h"

#include <assert.h>
#include <lib/sparse_array.h>
#include <stdio.h>

sparse_array_t* sparse_array_create(size_t element_size, size_t total_bytes) {
    phys_addr_t phys = pmm_alloc_page();
    virt_addr_t virt = vmm_alloc(&kernel_allocator, 1);
    printf("phys=%p virt=%p\n", (void*) phys, (void*) virt);
    vm_map_page(&kernel_allocator, virt, phys, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));

    sparse_array_t* array = (sparse_array_t*) virt;

    size_t num_pages = ALIGN_UP(total_bytes, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;
    size_t max_elements = total_bytes / element_size;
    printf("sparse_array_create: array=%p element_size=%zu total_bytes=%zu num_pages=%zu max_elements=%zu\n", array, element_size, total_bytes, num_pages, max_elements);
    printf("sparse_array_create: About to write to array->data at %p\n", &array->data);

    array->data = (void*) vmm_alloc(&kernel_allocator, num_pages);
    array->element_size = element_size;
    array->number_of_pages = max_elements;
    printf("sparse_array_create: created array at %p\n", array);
    return array;
}

void sparse_array_destroy(sparse_array_t* array) {
    for(size_t i = 0; i < array->number_of_pages; i++) {
        void* element = sparse_array_access(array, i);
        if(element) {
            virt_addr_t addr = (virt_addr_t) element;
            pmm_free_page(vm_resolve(&kernel_allocator, addr));
            vm_unmap_page(&kernel_allocator, addr);
        }
    }

    virt_addr_t addr = (virt_addr_t) array;
    vm_unmap_page(&kernel_allocator, addr);
    pmm_free_page(vm_resolve(&kernel_allocator, addr));
    vmm_free(&kernel_allocator, addr);
}

void* sparse_array_access(sparse_array_t* array, size_t index) {
    assert(index < array->number_of_pages && "Index out of bounds in sparse_array_access");

    virt_addr_t base_addr = (virt_addr_t) array->data;
    virt_addr_t addr = base_addr + (index * array->element_size);

    phys_addr_t phys_addr = vm_resolve(&kernel_allocator, addr);
    if(phys_addr == 0) {
        return nullptr;
    }

    return (void*) addr;
}

void* sparse_array_access_demand(sparse_array_t* array, size_t index) {
    printf("sparse_array_access_demand: array=%p index=%zu length=%zu\n", array, index, array->number_of_pages);
    assert(index < array->number_of_pages && "Index out of bounds in sparse_array_access_demand");
    virt_addr_t base_addr = (virt_addr_t) array->data;
    virt_addr_t addr = base_addr + (index * array->element_size);

    phys_addr_t phys_addr = vm_resolve(&kernel_allocator, addr);
    if(phys_addr == 0) {
        phys_addr_t new_page = pmm_alloc_page();
        vm_map_page(&kernel_allocator, addr, new_page, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
    }

    return (void*) addr;
}
