#include <arch/internal/cr.h>
#include <arch/internal/cpuid.h>
#include <arch/msr.h>
#include <common/arch.h>
#include <common/ipi.h>
#include <memory/memory.h>
#include <common/requests.h>
#include <memory/pagedb.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <rbtree.h>
#include <string.h>

typedef struct {
    uint64_t entries[512];
} __attribute__((aligned(4096))) __page_table_t;

static bool write_combing_supported = false;

#define PAGE_PRESENT_BIT (1ULL << 0)
#define PAGE_RW_BIT (1ULL << 1)

#define PAGE_USER_BIT (1ULL << 2)

#define PAGE_WRITE_THROUGH_BIT (1ULL << 3)
#define PAGE_CACHE_DISABLE_BIT (1ULL << 4)
#define PAGE_GLOBAL_BIT (1ULL << 8)

#define PAGE_EXECUTE_DISABLE_BIT (1ULL << 63)

#define SMALL_PAGE_PAT_BIT (1ULL << 7)
#define SMALL_PAGE_ADDRESS_MASK 0x000ffffffffff000ull

#define LARGE_PAGE_PAGE_SIZE_BIT (1ULL << 7)
#define LARGE_PAGE_PAT_BIT (1ULL << 12)
#define LARGE_PAGE_ADDRESS_MASK 0x000fffffffff0000ull


#define PAGE_PAT_BIT(page_size) ((page_size) == PAGE_SIZE_SMALL ? SMALL_PAGE_PAT_BIT : LARGE_PAGE_PAT_BIT)
#define PAGE_ADDRESS_MASK(page_size) ((page_size) == PAGE_SIZE_SMALL ? SMALL_PAGE_ADDRESS_MASK : LARGE_PAGE_ADDRESS_MASK)

typedef enum {
    PAGE_LEVEL_PML5 = 5,
    PAGE_LEVEL_PML4 = 4,
    PAGE_LEVEL_PDPT = 3,
    PAGE_LEVEL_PD = 2,
    PAGE_LEVEL_PT = 1,
} page_level_t;

#define PTE_INDEX(va, bit) (((va) & ((uintptr_t) 0x1ff << (bit))) >> (bit))

#define PML5_INDEX(va) PTE_INDEX(va, 48)
#define PML4_INDEX(va) PTE_INDEX(va, 39)
#define PDPT_INDEX(va) PTE_INDEX(va, 30)
#define PD_INDEX(va) PTE_INDEX(va, 21)
#define PT_INDEX(va) PTE_INDEX(va, 12)

uint64_t virt_to_index(virt_addr_t virt, page_level_t level) {
    switch(level) {
        case PAGE_LEVEL_PML5: return PML5_INDEX(virt);
        case PAGE_LEVEL_PML4: return PML4_INDEX(virt);
        case PAGE_LEVEL_PDPT: return PDPT_INDEX(virt);
        case PAGE_LEVEL_PD:   return PD_INDEX(virt);
        case PAGE_LEVEL_PT:   return PT_INDEX(virt);
    }
    __builtin_unreachable();
}

uint64_t index_to_virt(uint64_t index, page_level_t level) {
    switch(level) {
        case PAGE_LEVEL_PML5: return (index & 0x1FF) << 48;
        case PAGE_LEVEL_PML4: return (index & 0x1FF) << 39;
        case PAGE_LEVEL_PDPT: return (index & 0x1FF) << 30;
        case PAGE_LEVEL_PD:   return (index & 0x1FF) << 21;
        case PAGE_LEVEL_PT:   return (index & 0x1FF) << 12;
    }
    __builtin_unreachable();
}

uint64_t level_to_page_size(page_level_t level) {
    switch(level) {
        // case PAGE_LEVEL_PML5: return 68719476736;
        // case PAGE_LEVEL_PML4: return 134217728;
        case PAGE_LEVEL_PDPT: return 262144;
        case PAGE_LEVEL_PD:   return 512;
        case PAGE_LEVEL_PT:   return 1;

        default: __builtin_unreachable();
    }
    __builtin_unreachable();
}


// fuck x86_64 and it's stupid fucking paging entries because now this has to take the fucking page size into account
#define PAGE_CACHE_WRITE_COMBINE(page_size) (PAGE_PAT_BIT(page_size) | PAGE_CACHE_DISABLE_BIT)


uint64_t convert_access_flags(vm_access_t privilege) {
    switch(privilege) {
        case VM_ACCESS_KERNEL: return 0;
        case VM_ACCESS_USER:   return PAGE_USER_BIT;
    }
    __builtin_unreachable();
}

uint64_t convert_cache_flags(vm_cache_t cache, page_size_t page_size) {
    switch(cache) {
        case VM_CACHE_NORMAL:        return PAGE_WRITE_THROUGH_BIT;
        case VM_CACHE_DISABLE:       return PAGE_CACHE_DISABLE_BIT;
        case VM_CACHE_WRITE_THROUGH: return PAGE_WRITE_THROUGH_BIT;
        case VM_CACHE_WRITE_COMBINE: return PAGE_CACHE_WRITE_COMBINE(page_size);
    }
    __builtin_unreachable();
}

phys_addr_t __alloc_entry() {
    phys_addr_t phys = pmm_alloc_page();
    virt_addr_t virt = TO_HHDM(phys);
    memset((void*) virt, 0, 4096);
    return phys;
}


uint64_t* next_or_allocate(uint64_t* root, int idx, uint64_t flags) {
    if(!((root[idx] & PAGE_PRESENT_BIT) > 0)) {
        phys_addr_t new_table_phys = __alloc_entry();
        root[idx] = (new_table_phys & SMALL_PAGE_ADDRESS_MASK) | (flags & 0xfff);
    }

    phys_addr_t next_table_phys = root[idx] & SMALL_PAGE_ADDRESS_MASK;
    return (uint64_t*) TO_HHDM(next_table_phys);
}

uint64_t* next_if_exists(uint64_t* root, int idx) {
    if(!((root[idx] & PAGE_PRESENT_BIT) > 0)) {
        return NULL;
    }

    phys_addr_t next_table_phys = root[idx] & SMALL_PAGE_ADDRESS_MASK;
    return (uint64_t*) TO_HHDM(next_table_phys);
}

void vm_map_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, size_t page_count, vm_access_t access, vm_cache_t cache, vm_flags_t flags) {
    for(size_t i = 0; i < page_count; i++) {
        vm_map_page(allocator, virt_addr + (i * PAGE_SIZE_DEFAULT), phys_addr + (i * PAGE_SIZE_DEFAULT), access, cache, flags);
    }
}

void vm_unmap_pages_continuous(vm_allocator_t* allocator, virt_addr_t virt_addr, size_t page_count) {
    arch_memory_barrier();
    for(size_t i = 0; i < page_count; i++) {
        vm_unmap_page(allocator, virt_addr + (i * PAGE_SIZE_DEFAULT));
    }
    arch_memory_barrier();
}


void vm_map_page(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t phys_addr, vm_access_t access, vm_cache_t cache, vm_flags_t flags) {
    vm_flags_data_t flags_data = convert_vm_flags(flags);
    arch_memory_barrier();

    uint64_t imtermediate_flags = PAGE_PRESENT_BIT | PAGE_RW_BIT;

    if(access == VM_ACCESS_USER) {
        imtermediate_flags |= PAGE_USER_BIT;
    }

    uint64_t* pml4 = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);

    uint64_t* pdpt = next_or_allocate(pml4, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PML4), imtermediate_flags);
    uint64_t* pd = next_or_allocate(pdpt, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PDPT), imtermediate_flags);
    uint64_t* pt = next_or_allocate(pd, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PD), imtermediate_flags);
    uint64_t page_entry = (phys_addr & SMALL_PAGE_ADDRESS_MASK) | (flags_data.present ? PAGE_PRESENT_BIT : 0) | (flags_data.write ? PAGE_RW_BIT : 0) | convert_access_flags(access) | convert_cache_flags(cache, PAGE_SIZE_SMALL);

    uint16_t pt_index = (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT);
    pt[pt_index] = page_entry;
    arch_memory_barrier();
}

void vm_reprotect_page(vm_allocator_t* allocator, virt_addr_t virt_addr, vm_access_t access, vm_cache_t cache, vm_flags_t flags) {
    vm_flags_data_t flags_data = convert_vm_flags(flags);
    uint64_t imtermediate_flags = PAGE_PRESENT_BIT | PAGE_RW_BIT;

    if(access == VM_ACCESS_USER) {
        imtermediate_flags |= PAGE_USER_BIT;
    }

    uint64_t* pml4 = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);

    uint64_t* pdpt = next_or_allocate(pml4, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PML4), imtermediate_flags);
    uint64_t* pd = next_or_allocate(pdpt, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PDPT), imtermediate_flags);
    uint64_t* pt = next_or_allocate(pd, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PD), imtermediate_flags);
    uint64_t page_new_flags = (flags_data.present ? PAGE_PRESENT_BIT : 0) | (flags_data.write ? PAGE_RW_BIT : 0) | convert_access_flags(access) | convert_cache_flags(cache, PAGE_SIZE_SMALL);

    uint64_t old_entry = pt[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT)];
    uint64_t page_entry = (old_entry & PAGE_ADDRESS_MASK(PAGE_SIZE_SMALL)) | page_new_flags;

    pt[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT)] = page_entry;
    vm_flush_page_dispatch(virt_addr);
}

phys_addr_t vm_resolve(vm_allocator_t* allocator, virt_addr_t virt_addr) {
    uint64_t* pml4 = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);

    uint64_t* pdpt = next_if_exists(pml4, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PML4));
    if(pdpt == NULL) {
        return 0;
    }

    uint64_t* pd = next_if_exists(pdpt, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PDPT));
    if(pd == NULL) {
        return 0;
    }

    uint64_t* pt = next_if_exists(pd, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PD));
    if(pt == NULL) {
        return 0;
    }

    uint64_t page_entry = pt[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT)];
    if(!(page_entry & PAGE_PRESENT_BIT)) {
        return 0;
    }

    return page_entry & SMALL_PAGE_ADDRESS_MASK;
}
void vm_unmap_page(vm_allocator_t* allocator, virt_addr_t virt_addr) {
    arch_memory_barrier();
    uint64_t* pml4 = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);

    uint64_t* pdpt = next_if_exists(pml4, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PML4));
    if(pdpt == NULL) {
        return;
    }

    uint64_t* pd = next_if_exists(pdpt, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PDPT));
    if(pd == NULL) {
        return;
    }

    uint64_t* pt = next_if_exists(pd, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PD));
    if(pt == NULL) {
        return;
    }

    pt[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT)] = 0;
    vm_flush_page_dispatch(virt_addr);
    arch_memory_barrier();
}


void vm_flush_page_raw(virt_addr_t addr) {
    arch_memory_barrier();
    asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
    arch_memory_barrier();
}

void vm_flush_page_dispatch(virt_addr_t addr) {
    vm_flush_page_raw(addr);
    ipi_t ipi;
    ipi.type = IPI_TLB_FLUSH;
    ipi.tlb_flush.virt_addr = addr;
    ipi_broadcast(&ipi);
}

#define PAT_UNCACHEABLE 0
#define PAT_WRITE_COMBINING 1
#define PAT_WRITE_THROUGH 4
#define PAT_WRITE_PROTECT 5
#define PAT_WRITE_BACK 6
#define PAT_UNCACHED 7

void __setup_pat() {
    // read cpuid 0x01 and bit 16 on edx
    uint32_t edx = __cpuid(CPUID_GET_FEATURES, 0, CPUID_EDX);
    if((edx & CPUID_GET_FEATURES_EDX_PAT) == 0) {
        printf("cpu does not support pat, write combining will be unavailable");
        return;
    }

    write_combing_supported = true;

    // Default setup is (assuming bootloader doesn't touch it which it does but we don't care)
    //
    // PAT0: Write back      |
    // PAT1: Write through   | PWT
    // PAT2: Uncached        | PCD
    // PAT3: Uncacheable     | PCD PWT
    // PAT4: Write back      | PAT
    // PAT5: Write through   | PAT PWT
    // PAT6: Uncached        | PAT PCD
    // PAT7: Uncacheable     | PAT PCD PWT

    // Our setup
    //
    // PAT0: Write back      |
    // PAT1: Write through   | PWT
    // PAT2: Uncached        | PCD
    // PAT3: Uncacheable     | PCD PWT
    // PAT4: Write combining | PAT
    // PAT5: Uncachable      | PAT PWT
    // PAT6: Uncachable      | PAT PCD
    // PAT7: Uncachable      | PAT PCD PWT

    uint8_t pat0 = PAT_WRITE_BACK;
    uint8_t pat1 = PAT_WRITE_THROUGH;
    uint8_t pat2 = PAT_UNCACHED;
    uint8_t pat3 = PAT_UNCACHEABLE;
    uint8_t pat4 = PAT_WRITE_COMBINING;
    uint8_t pat5 = PAT_UNCACHEABLE; // UNUSED
    uint8_t pat6 = PAT_UNCACHEABLE; // UNUSED
    uint8_t pat7 = PAT_UNCACHEABLE; // UNUSED

    uint64_t pat = pat0 | ((uint64_t) pat1 << 8) | ((uint64_t) pat2 << 16) | ((uint64_t) pat3 << 24) | ((uint64_t) pat4 << 32) | ((uint64_t) pat5 << 40) | ((uint64_t) pat6 << 48) | ((uint64_t) pat7 << 56);

    __wrmsr(IA32_PAT_MSR, pat);
}

void vm_address_space_switch(vm_allocator_t* allocator) {
    arch_memory_barrier();
    __write_cr3(allocator->kernel_paging_structures_base);
    arch_memory_barrier();
}

phys_addr_t vm_address_space_switch_raw(phys_addr_t cr3) {
    arch_memory_barrier();
    phys_addr_t old_cr3 = __read_cr3();
    arch_memory_barrier();
    __write_cr3(cr3);
    arch_memory_barrier();
    return old_cr3;
}

void vm_paging_setup_user(vm_allocator_t* allocator) {
    allocator->kernel_paging_structures_base = __alloc_entry();
    uint64_t* pml4_kernel = (uint64_t*) TO_HHDM(kernel_allocator.kernel_paging_structures_base);
    uint64_t* pml4_user = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);

    memcpy(pml4_user + 256, pml4_kernel + 256, 256 * sizeof(uint64_t));
}

void vm_paging_bsp_init(vm_allocator_t* allocator) {
    allocator->kernel_paging_structures_base = __alloc_entry();
    uint64_t* pml4 = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);
    for(int i = 256; i < 512; i++) {
        pml4[i] = PAGE_PRESENT_BIT | PAGE_RW_BIT | (__alloc_entry() & SMALL_PAGE_ADDRESS_MASK);
    }
    __setup_pat();
}

void vm_paging_ap_init(vm_allocator_t* allocator) {
    (void) allocator;
    __setup_pat();
}

bool vm_handle_page_fault(vm_fault_reason_t reason, virt_addr_t fault_address) {
    printf("Page fault at address 0x%lx, reason %u\n", fault_address, reason);
    if(reason == VM_FAULT_UKKNOWN) {
        return false;
    }

    vm_node_t* node = (vm_node_t*) rb_find_within(&kernel_allocator.vm_tree, fault_address);
    if(node == NULL) {
        return false;
    }

    printf("Page fault handler: got vm_node at %p (demand=%u)\n", node, node->options_type == VM_OPTIONS_DEMAND);

    if(node->options_type == VM_OPTIONS_DEMAND) {
        phys_addr_t phys = pmm_alloc_page();
        vm_map_page(&kernel_allocator, fault_address, phys, node->options.demand.access, node->options.demand.cache, node->options.demand.flags);
        if(node->options.demand.zero_fill) {
            memset((void*) fault_address, 0, PAGE_SIZE_DEFAULT);
        }
        return true;
    }

    return false;
}

void vm_remap_page(vm_allocator_t* allocator, virt_addr_t virt_addr, phys_addr_t new_phys_addr) {
    arch_memory_barrier();
    uint64_t* pml4 = (uint64_t*) TO_HHDM(allocator->kernel_paging_structures_base);

    uint64_t* pdpt = next_if_exists(pml4, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PML4));
    if(pdpt == NULL) {
        return;
    }

    uint64_t* pd = next_if_exists(pdpt, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PDPT));
    if(pd == NULL) {
        return;
    }

    uint64_t* pt = next_if_exists(pd, (uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PD));
    if(pt == NULL) {
        return;
    }

    uint64_t old_entry = pt[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT)];
    uint64_t page_entry = (new_phys_addr & SMALL_PAGE_ADDRESS_MASK) | (old_entry & (~SMALL_PAGE_ADDRESS_MASK));
    printf("Remapping virtual address 0x%lx to physical address 0x%lx old_entry=0x%lx new_entry=0x%lx\n", virt_addr, new_phys_addr, old_entry, page_entry);
    pt[(uint16_t) virt_to_index(virt_addr, PAGE_LEVEL_PT)] = page_entry | PAGE_PRESENT_BIT;
    vm_flush_page_dispatch(virt_addr);
    arch_memory_barrier();
}
