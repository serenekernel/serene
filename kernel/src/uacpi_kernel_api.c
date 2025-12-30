#include "memory/vmm.h"

#include <common/io.h>
#include <common/memory.h>
#include <common/requests.h>
#include <stdio.h>
#include <uacpi/kernel_api.h>

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr* out_rsdp_address) {
    uintptr_t rsdp_virt = (uintptr_t) rsdp_request.response->address;
    uintptr_t rsdp_phys = rsdp_virt - hhdm_request.response->offset;
    printf("rsdp: 0x%llx @ 0x%llx\n", rsdp_virt, rsdp_phys);

    *out_rsdp_address = rsdp_phys;
    return UACPI_STATUS_OK;
}

/*
 * Map a physical memory range starting at 'addr' with length 'len', and return
 * a virtual address that can be used to access it.
 *
 * NOTE: 'addr' may be misaligned, in this case the host is expected to round it
 *       down to the nearest page-aligned boundary and map that, while making
 *       sure that at least 'len' bytes are still mapped starting at 'addr'. The
 *       return value preserves the misaligned offset.
 *
 *       Example for uacpi_kernel_map(0x1ABC, 0xF00):
 *           1. Round down the 'addr' we got to the nearest page boundary.
 *              Considering a PAGE_SIZE of 4096 (or 0x1000), 0x1ABC rounded down
 *              is 0x1000, offset within the page is 0x1ABC - 0x1000 => 0xABC
 *           2. Requested 'len' is 0xF00 bytes, but we just rounded the address
 *              down by 0xABC bytes, so add those on top. 0xF00 + 0xABC => 0x19BC
 *           3. Round up the final 'len' to the nearest PAGE_SIZE boundary, in
 *              this case 0x19BC is 0x2000 bytes (2 pages if PAGE_SIZE is 4096)
 *           4. Call the VMM to map the aligned address 0x1000 (from step 1)
 *              with length 0x2000 (from step 3). Let's assume the returned
 *              virtual address for the mapping is 0xF000.
 *           5. Add the original offset within page 0xABC (from step 1) to the
 *              resulting virtual address 0xF000 + 0xABC => 0xFABC. Return it
 *              to uACPI.
 */
void* uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    phys_addr_t phys_base = ALIGN_DOWN(addr, PAGE_SIZE_DEFAULT);
    size_t page_count = ALIGN_UP(len, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;

    virt_addr_t virt_base = vmm_alloc(&kernel_allocator, page_count);
    printf("uacpi mapping 0x%llx -> 0x%llx wanted size 0x%llx got 0x%llx with offset 0x%llx\n", phys_base, virt_base, len, page_count * PAGE_SIZE_DEFAULT, (addr - phys_base));
    vm_map_pages_continuous(&kernel_allocator, virt_base, phys_base, page_count, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
    printf("dump: 0x%llx\n", mmio_read_u64(virt_base));
    return (void*) (virt_base + (addr - phys_base));
}

void uacpi_kernel_unmap(void* addr, uacpi_size len) {
    virt_addr_t virt_base = ALIGN_DOWN((virt_addr_t) addr, PAGE_SIZE_DEFAULT);
    size_t page_count = ALIGN_UP(len, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;
    printf("uacpi unmapping 0x%llx - 0x%llx\n", virt_base, page_count * PAGE_SIZE_DEFAULT);

    vm_unmap_pages_continuous(&kernel_allocator, virt_base, page_count);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char* str) {
    if(level == UACPI_LOG_DEBUG) { printf("uacpi debug %s", str); }
    if(level == UACPI_LOG_TRACE) { printf("uacpi trace %s", str); }
    if(level == UACPI_LOG_INFO) { printf("uacpi info %s", str); }
    if(level == UACPI_LOG_WARN) { printf("uacpi warn %s", str); }
    if(level == UACPI_LOG_ERROR) { printf("uacpi error %s", str); }
}
