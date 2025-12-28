#include "common/memory.h"
#include "memory/vmm.h"

#include <arch/gdt.h>
#include <stdint.h>

typedef struct {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t limit_high_flags;
    uint8_t base_high;
} __attribute__((packed)) gdt_entry_t;

typedef struct {
    uint32_t __reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t __reserved1;
    uint64_t ist[7];
    uint64_t __reserved2;
    uint16_t __reserved3;
    uint16_t io_map_base;
} __attribute__((packed)) tss_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) gdtr_t;

gdt_entry_t gdt[8] = {
    {}, // null @ 0x0
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0x9a, .limit_high_flags = 0xA0, .base_high = 0 }, // kernel code @ 0x08
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0x92, .limit_high_flags = 0xC0, .base_high = 0 }, // kernel data @ 0x10
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0xfa, .limit_high_flags = 0xA0, .base_high = 0 }, // 32 bit user code @ 0x18
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0xf2, .limit_high_flags = 0xC0, .base_high = 0 }, // 64 bit user data @ 0x20
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0xfa, .limit_high_flags = 0xA0, .base_high = 0 }, // 64 bit user code @ 0x28
    {}, // tss lo @ 0x30
    {}  // tss hi @ 0x38
};


void gdt_set_tss(tss_entry_t* tss) {
    gdt[6].limit_low = sizeof(tss_entry_t) & 0xFFFF;
    gdt[6].base_low = (uint32_t) ((uintptr_t) tss & 0xFFFF);
    gdt[6].base_mid = (uint8_t) (((uintptr_t) tss >> 16) & 0xFF);
    gdt[6].access = 0x89; // present, ring 0, type 9
    gdt[6].limit_high_flags = (uint8_t) (((sizeof(tss_entry_t) >> 16) & 0x0F));
    gdt[6].base_high = (uint8_t) (((uintptr_t) tss >> 24) & 0xFF);
    gdt[7].base_low = (uint32_t) (((uintptr_t) tss >> 32) & 0xFFFFFFFF);
}


extern void __load_gdt(gdtr_t* gdtr, uint16_t code_sel, uint16_t data_sel, uint16_t tss_sel);

void setup_gdt() {
    phys_addr_t tss_phys = pmm_alloc_page();
    virt_addr_t tss_virt = vmm_alloc(&kernel_allocator, 1);
    vm_map_page(&kernel_allocator, tss_virt, tss_phys, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
    memset((void*) tss_virt, 0, PAGE_SIZE_DEFAULT);

    phys_addr_t ist1_stack_phys = pmm_alloc_page();
    virt_addr_t ist1_stack_virt = vmm_alloc(&kernel_allocator, 1);
    vm_map_page(&kernel_allocator, ist1_stack_virt, ist1_stack_phys, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
    memset((void*) ist1_stack_virt, 0, PAGE_SIZE_DEFAULT);

    phys_addr_t ist2_stack_phys = pmm_alloc_page();
    virt_addr_t ist2_stack_virt = vmm_alloc(&kernel_allocator, 1);
    vm_map_page(&kernel_allocator, ist2_stack_virt, ist2_stack_phys, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
    memset((void*) ist2_stack_virt, 0, PAGE_SIZE_DEFAULT);


    tss_entry_t* tss = (tss_entry_t*) tss_virt;
    tss->ist[1] = ist1_stack_virt + PAGE_SIZE_DEFAULT;
    tss->ist[2] = ist2_stack_virt + PAGE_SIZE_DEFAULT;
    gdt_set_tss(tss);

    gdtr_t gdtr;
    gdtr.limit = sizeof(gdt) - 1;
    gdtr.base = (uint64_t) &gdt;
    __load_gdt(&gdtr, 0x08, 0x10, 0x30);
}
