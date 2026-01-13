#include <common/arch.h>
#include <common/ipi.h>
#include <common/memory.h>
#include <common/requests.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <string.h>

typedef struct {
    uint64_t entries[512];
} __attribute__((aligned(4096))) __page_table_t;

// aarch64 translation table descriptor bits
#define DESC_VALID (1ULL << 0)
#define DESC_TABLE (1ULL << 1) // for level 0-2
#define DESC_PAGE (1ULL << 1) // for level 3 (with valid bit)

// access permissions (AP[2:1])
#define DESC_AP_RW_EL1 (0ULL << 6) // rw, el1
#define DESC_AP_RW_ALL (1ULL << 6) // rw, elx
#define DESC_AP_RO_EL1 (2ULL << 6) // ro, el1
#define DESC_AP_RO_ALL (3ULL << 6) // ro, elx

// shareability
#define DESC_SH_NON_SHAREABLE (0ULL << 8)
#define DESC_SH_OUTER_SHAREABLE (2ULL << 8)
#define DESC_SH_INNER_SHAREABLE (3ULL << 8)

// access flag
#define DESC_AF (1ULL << 10)

// memory attributes index into MAIR_EL1
#define DESC_ATTR_IDX(x) (((uint64_t) (x)) << 2)

// execution permissions
#define DESC_UXN (1ULL << 54) // user execute never
#define DESC_PXN (1ULL << 53) // privileged execute never

// address masks
#define DESC_TABLE_ADDR_MASK 0x0000FFFFFFFFF000ULL
#define DESC_PAGE_ADDR_MASK 0x0000FFFFFFFFF000ULL

// memory attribute indirection register indices
#define MAIR_IDX_DEVICE_nGnRnE 0 // device memory, non-gathering, non-reordering, no early write ack
#define MAIR_IDX_NORMAL_NC 1 // normal memory, non-cacheable
#define MAIR_IDX_NORMAL_WT 2 // normal memory, write-through
#define MAIR_IDX_NORMAL_WB 3 // normal memory, write-back

// MAIR_EL1 attribute values
#define MAIR_DEVICE_nGnRnE 0x00ULL
#define MAIR_NORMAL_NC 0x44ULL // inner/outer non-cacheable
#define MAIR_NORMAL_WT 0xBBULL // inner/outer write-through, read/write allocate
#define MAIR_NORMAL_WB 0xFFULL // inner/outer write-back, read/write allocate

typedef enum {
    PAGE_LEVEL_L0 = 0,
    PAGE_LEVEL_L1 = 1,
    PAGE_LEVEL_L2 = 2,
    PAGE_LEVEL_L3 = 3,
} page_level_t;

#define TABLE_INDEX(va, level) (((va) >> (12 + (3 - (level)) * 9)) & 0x1FF)

#define L0_INDEX(va) TABLE_INDEX(va, PAGE_LEVEL_L0)
#define L1_INDEX(va) TABLE_INDEX(va, PAGE_LEVEL_L1)
#define L2_INDEX(va) TABLE_INDEX(va, PAGE_LEVEL_L2)
#define L3_INDEX(va) TABLE_INDEX(va, PAGE_LEVEL_L3)

// Check if virtual address is in higher half (kernel space)
static inline bool is_higher_half(virt_addr_t virt) {
    return virt >= 0xFFFF000000000000ULL;
}

uint64_t virt_to_index(virt_addr_t virt, page_level_t level) {
    return TABLE_INDEX(virt, level);
}

uint64_t index_to_virt(uint64_t index, page_level_t level) {
    return (index & 0x1FF) << (12 + (3 - level) * 9);
}

uint64_t convert_access_flags(vm_access_t access, bool writable) {
    switch(access) {
        case VM_ACCESS_KERNEL: return writable ? DESC_AP_RW_EL1 : DESC_AP_RO_EL1;
        case VM_ACCESS_USER:   return writable ? DESC_AP_RW_ALL : DESC_AP_RO_ALL;
    }
    __builtin_unreachable();
}

uint64_t convert_cache_flags(vm_cache_t cache) {
    switch(cache) {
        case VM_CACHE_NORMAL:        return DESC_ATTR_IDX(MAIR_IDX_NORMAL_WB);
        case VM_CACHE_DISABLE:       return DESC_ATTR_IDX(MAIR_IDX_DEVICE_nGnRnE);
        case VM_CACHE_WRITE_THROUGH: return DESC_ATTR_IDX(MAIR_IDX_NORMAL_WT);
        case VM_CACHE_WRITE_COMBINE: return DESC_ATTR_IDX(MAIR_IDX_NORMAL_NC);
    }
    __builtin_unreachable();
}

phys_addr_t __alloc_entry() {
    phys_addr_t phys = pmm_alloc_page();
    virt_addr_t virt = TO_HHDM(phys);
    memset((void*) virt, 0, 4096);
    __asm__ volatile("dsb ishst" ::: "memory");
    return phys;
}

uint64_t* next_or_allocate(uint64_t* root, int idx, uint64_t flags) {
    if(!(root[idx] & DESC_VALID)) {
        phys_addr_t new_table_phys = __alloc_entry();
        // For intermediate levels (L0-L2), use table descriptor
        root[idx] = (new_table_phys & DESC_TABLE_ADDR_MASK) | DESC_TABLE | DESC_VALID | (flags & 0xfff);
        __asm__ volatile("dsb ishst" ::: "memory");
    }

    phys_addr_t next_table_phys = root[idx] & DESC_TABLE_ADDR_MASK;
    return (uint64_t*) TO_HHDM(next_table_phys);
}

uint64_t* next_if_exists(uint64_t* root, int idx) {
    if(!(root[idx] & DESC_VALID)) {
        return NULL;
    }

    phys_addr_t next_table_phys = root[idx] & DESC_TABLE_ADDR_MASK;
    return (uint64_t*) TO_HHDM(next_table_phys);
}

void vm_map_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, size_t page_count, vm_access_t access, vm_cache_t cache, vm_protection_flags_t protection) {
    for(size_t i = 0; i < page_count; i++) {
        vm_map_page(allocator, virt_addr + (i * PAGE_SIZE_DEFAULT), phys_addr + (i * PAGE_SIZE_DEFAULT), access, cache, protection);
    }
}

void vm_map_page(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, vm_access_t access, vm_cache_t cache, vm_protection_flags_t protection) {
    uint64_t intermediate_flags = 0;

    phys_addr_t page_table_base = is_higher_half(virt_addr) ? allocator->kernel_paging_structures_base : allocator->paging_structures_base;
    uint64_t* l0 = (uint64_t*) TO_HHDM(page_table_base);

    uint64_t* l1 = next_or_allocate(l0, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L0), intermediate_flags);
    uint64_t* l2 = next_or_allocate(l1, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L1), intermediate_flags);
    uint64_t* l3 = next_or_allocate(l2, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L2), intermediate_flags);

    uint64_t page_entry = (phys_addr & DESC_PAGE_ADDR_MASK);
    if(protection.present) {
        page_entry |= DESC_VALID | DESC_PAGE;
    }
    page_entry |= DESC_AF;
    page_entry |= convert_access_flags(access, protection.write);
    page_entry |= convert_cache_flags(cache);
    if(cache == VM_CACHE_NORMAL || cache == VM_CACHE_WRITE_THROUGH) {
        page_entry |= DESC_SH_INNER_SHAREABLE;
    }
    if(!protection.execute) {
        page_entry |= DESC_UXN | DESC_PXN;
    } else {
        if(access == VM_ACCESS_KERNEL) {
            page_entry |= DESC_UXN;
        }
        if(access == VM_ACCESS_USER) {
            page_entry |= DESC_PXN;
        }
    }

    l3[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L3)] = page_entry;
}

void vm_reprotect_page(vm_allocator_t* allocator, virt_addr_t virt_addr, vm_access_t access, vm_cache_t cache, vm_protection_flags_t protection) {
    uint64_t intermediate_flags = 0;

    phys_addr_t page_table_base = is_higher_half(virt_addr) ? allocator->kernel_paging_structures_base : allocator->paging_structures_base;
    uint64_t* l0 = (uint64_t*) TO_HHDM(page_table_base);

    uint64_t* l1 = next_or_allocate(l0, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L0), intermediate_flags);
    uint64_t* l2 = next_or_allocate(l1, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L1), intermediate_flags);
    uint64_t* l3 = next_or_allocate(l2, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L2), intermediate_flags);

    uint64_t old_entry = l3[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L3)];
    uint64_t page_entry = (old_entry & DESC_PAGE_ADDR_MASK);

    if(protection.present) {
        page_entry |= DESC_VALID | DESC_PAGE;
    }

    page_entry |= DESC_AF;
    page_entry |= convert_access_flags(access, protection.write);
    page_entry |= convert_cache_flags(cache);

    if(cache == VM_CACHE_NORMAL || cache == VM_CACHE_WRITE_THROUGH) {
        page_entry |= DESC_SH_INNER_SHAREABLE;
    }

    if(!protection.execute) {
        page_entry |= DESC_UXN | DESC_PXN;
    } else {
        if(access == VM_ACCESS_KERNEL) {
            page_entry |= DESC_UXN;
        }
    }

    if(!protection.global) {
        page_entry |= (1ULL << 11);
    }

    l3[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L3)] = page_entry;
    vm_flush_page_dispatch(virt_addr);
}

phys_addr_t vm_resolve(vm_allocator_t* allocator, virt_addr_t virt_addr) {
    phys_addr_t page_table_base = is_higher_half(virt_addr) ? allocator->kernel_paging_structures_base : allocator->paging_structures_base;
    uint64_t* l0 = (uint64_t*) TO_HHDM(page_table_base);

    uint64_t* l1 = next_if_exists(l0, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L0));
    if(l1 == NULL) {
        return 0;
    }

    uint64_t* l2 = next_if_exists(l1, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L1));
    if(l2 == NULL) {
        return 0;
    }

    uint64_t* l3 = next_if_exists(l2, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L2));
    if(l3 == NULL) {
        return 0;
    }

    uint64_t page_entry = l3[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L3)];
    if(!(page_entry & DESC_VALID)) {
        return 0;
    }

    return page_entry & DESC_PAGE_ADDR_MASK;
}

void vm_unmap_page(vm_allocator_t* allocator, virt_addr_t virt_addr) {
    phys_addr_t page_table_base = is_higher_half(virt_addr) ? allocator->kernel_paging_structures_base : allocator->paging_structures_base;
    uint64_t* l0 = (uint64_t*) TO_HHDM(page_table_base);

    uint64_t* l1 = next_if_exists(l0, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L0));
    if(l1 == NULL) {
        return;
    }

    uint64_t* l2 = next_if_exists(l1, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L1));
    if(l2 == NULL) {
        return;
    }

    uint64_t* l3 = next_if_exists(l2, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L2));
    if(l3 == NULL) {
        return;
    }

    l3[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_L3)] = 0;
    vm_flush_page_dispatch(virt_addr, 1);
}

void vm_unmap_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, size_t page_count) {
    for(size_t i = 0; i < page_count; i++) {
        vm_unmap_page(allocator, virt_addr + (i * PAGE_SIZE_DEFAULT));
    }
}

void vm_flush_page_raw(virt_addr_t addr) {
    arch_memory_barrier();
    __asm__ volatile("tlbi vaae1is, %0" ::"r"(addr >> 12) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
    arch_memory_barrier();
}

void vm_flush_page_dispatch(virt_addr_t addr) {
    vm_flush_page_raw(addr);
    ipi_t ipi;
    ipi.type = IPI_TLB_FLUSH;
    ipi.tlb_flush.virt_addr = addr;
    ipi_broadcast(&ipi);
}

static inline void __setup_mair() {
    uint64_t mair = (MAIR_DEVICE_nGnRnE << (MAIR_IDX_DEVICE_nGnRnE * 8)) | (MAIR_NORMAL_NC << (MAIR_IDX_NORMAL_NC * 8)) | (MAIR_NORMAL_WT << (MAIR_IDX_NORMAL_WT * 8)) | (MAIR_NORMAL_WB << (MAIR_IDX_NORMAL_WB * 8));

    __asm__ volatile("msr mair_el1, %0" ::"r"(mair));
    __asm__ volatile("isb" ::: "memory");
}

static inline void __setup_tcr() {
    uint64_t tcr = 0;

    tcr |= (16ULL << 0); // T0SZ: size offset for TTBR0_EL1 (64 - 48 = 16)
    tcr |= (1ULL << 8); // IRGN0: inner cacheability for TTBR0 (normal, inner write-back read-allocate write-allocate cacheable)
    tcr |= (1ULL << 10); // ORGN0: outer cacheability for TTBR0 (normal, outer write-back read-allocate write-allocate cacheable)
    tcr |= (3ULL << 12); // SH0: shareability for TTBR0 (inner shareable)
    tcr |= (0ULL << 14); // TG0: granule size for TTBR0 (4kb)
    tcr |= (16ULL << 16); // T1SZ: size offset for TTBR1_EL1 (64 - 48 = 16)
    tcr |= (1ULL << 24); // IRGN1: inner cacheability for TTBR1
    tcr |= (1ULL << 26); // ORGN1: outer cacheability for TTBR1
    tcr |= (3ULL << 28); // SH1: shareability for TTBR1 (inner shareable)
    tcr |= (2ULL << 30); // TG1: granule size for TTBR1 (4kb)
    tcr |= (5ULL << 32); // IPS: intermediate physical address size (48 bits - 0b101)
    printf("about to load\n");
    __asm__ volatile("msr tcr_el1, %0" ::"r"(tcr));
    printf("mbm\n");
    __asm__ volatile("isb" ::: "memory");
    printf("tcr done\n");
}

void vm_address_space_switch(vm_allocator_t* allocator) {
    arch_memory_barrier();
    __asm__ volatile("msr ttbr0_el1, %0" ::"r"(allocator->paging_structures_base));
    __asm__ volatile("msr ttbr1_el1, %0" ::"r"(allocator->kernel_paging_structures_base));
    __asm__ volatile("isb" ::: "memory");
    arch_memory_barrier();
}

void vm_paging_bsp_init(vm_allocator_t* allocator) {
    allocator->paging_structures_base = __alloc_entry();
    allocator->kernel_paging_structures_base = __alloc_entry();
    __setup_mair();
    printf("mair done\n");
    __setup_tcr();
    printf("tcr done\n");
}

void vm_paging_ap_init(vm_allocator_t* allocator) {
    (void) allocator;
    __setup_mair();
    __setup_tcr();
}
