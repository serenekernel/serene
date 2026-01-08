#include "arch/cpu_local.h"
#include "common/memory.h"
#include "memory/vmm.h"

#include <arch/gdt.h>
#include <common/cpu_local.h>
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
    gdt_entry_t entry;
    uint32_t base_ext;
    uint32_t __reserved;
} __attribute__((packed)) gdt_system_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) gdtr_t;


typedef struct {
    gdt_entry_t null;
    gdt_entry_t kernel_code;
    gdt_entry_t kernel_data;
    gdt_entry_t user_code_32;
    gdt_entry_t user_data;
    gdt_entry_t user_code;
    gdt_system_entry_t tss;
} __attribute__((packed)) gdt_t;

gdt_t gdt = {
    {}, // null @ 0x0
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0x9b, .limit_high_flags = 0xA0, .base_high = 0 }, // kernel code @ 0x08
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0x93, .limit_high_flags = 0xC0, .base_high = 0 }, // kernel data @ 0x10
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0xfb, .limit_high_flags = 0xA0, .base_high = 0 }, // 32 bit user code @ 0x18
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0xf3, .limit_high_flags = 0xC0, .base_high = 0 }, // 64 bit user data @ 0x20
    { .limit_low = 0, .base_low = 0, .base_mid = 0, .access = 0xfb, .limit_high_flags = 0xA0, .base_high = 0 }, // 64 bit user code @ 0x28
    {}, // tss @ 0x30
};


void gdt_set_tss(tss_t* tss) {
    gdt.tss.entry.limit_low = sizeof(tss_t) & 0xFFFF;
    gdt.tss.entry.base_low = (uint16_t) ((uintptr_t) tss & 0xFFFF);
    gdt.tss.entry.base_mid = (uint8_t) (((uintptr_t) tss >> 16) & 0xFF);
    gdt.tss.entry.access = 0x89; // present, ring 0, type 9
    gdt.tss.entry.limit_high_flags = (uint8_t) (((sizeof(tss_t) >> 16) & 0x0F));
    gdt.tss.entry.base_high = (uint8_t) (((uintptr_t) tss >> 24) & 0xFF);
    gdt.tss.base_ext = (uint32_t) ((uint64_t) tss >> 32);
    gdt.tss.__reserved = 0;
}

extern void __load_gdt(gdtr_t* gdtr, uint16_t code_sel, uint16_t data_sel, uint16_t tss_sel);

void setup_gdt() {
    virt_addr_t tss_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t rsp0_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t ist1_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t ist2_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t ist3_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);

    tss_t* tss = (tss_t*) tss_virt;
    // RSP0 - kernel stack for ring 0 (used when transitioning from ring 3)
    tss->rsp0 = rsp0_stack_virt + PAGE_SIZE_DEFAULT;
    // #NMI
    tss->ist[1] = ist1_stack_virt + PAGE_SIZE_DEFAULT;
    // #DF
    tss->ist[2] = ist2_stack_virt + PAGE_SIZE_DEFAULT;
    // #MC
    tss->ist[3] = ist3_stack_virt + PAGE_SIZE_DEFAULT;

    gdt_set_tss(tss);
    CPU_LOCAL_WRITE(cpu_tss, tss);

    gdtr_t gdtr;
    gdtr.limit = sizeof(gdt) - 1;
    gdtr.base = (uint64_t) &gdt;
    __load_gdt(&gdtr, 0x08, 0x10, 0x30);
}
