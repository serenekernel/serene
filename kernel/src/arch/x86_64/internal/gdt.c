#include <arch/cpu_local.h>
#include <memory/memory.h>
#include <memory/vmm.h>
#include <string.h>
#include <arch/internal/gdt.h>
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
    // Calculate TSS limit (size - 1)
    uint32_t tss_limit = sizeof(tss_t) - 1;

    gdt.tss.entry.limit_low = tss_limit & 0xFFFF;
    gdt.tss.entry.base_low = (uint16_t) ((uintptr_t) tss & 0xFFFF);
    gdt.tss.entry.base_mid = (uint8_t) (((uintptr_t) tss >> 16) & 0xFF);
    gdt.tss.entry.access = 0x89; // present, ring 0, type 9
    gdt.tss.entry.limit_high_flags = (uint8_t) ((tss_limit >> 16) & 0x0F);
    gdt.tss.entry.base_high = (uint8_t) (((uintptr_t) tss >> 24) & 0xFF);
    gdt.tss.base_ext = (uint32_t) ((uint64_t) tss >> 32);
    gdt.tss.__reserved = 0;
}

extern void __load_gdt(gdtr_t* gdtr, uint16_t code_sel, uint16_t data_sel, uint16_t tss_sel);

void setup_gdt() {
    // Allocate enough pages for the TSS (needs more than 1 page now with I/O bitmap)
    size_t tss_pages = (sizeof(tss_t) + PAGE_SIZE_DEFAULT - 1) / PAGE_SIZE_DEFAULT;
    virt_addr_t tss_virt = vmm_alloc_backed(&kernel_allocator, tss_pages, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t rsp0_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t ist1_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t ist2_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    virt_addr_t ist3_stack_virt = vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);

    tss_t* tss = (tss_t*) tss_virt;
    memset(tss, 0, sizeof(tss_t));

    // RSP0 - kernel stack for ring 0 (used when transitioning from ring 3)
    tss->rsp0 = rsp0_stack_virt + PAGE_SIZE_DEFAULT;
    // #NMI
    tss->ist[1] = ist1_stack_virt + PAGE_SIZE_DEFAULT;
    // #DF
    tss->ist[2] = ist2_stack_virt + PAGE_SIZE_DEFAULT;
    // #MC
    tss->ist[3] = ist3_stack_virt + PAGE_SIZE_DEFAULT;

    // Initialize I/O permission bitmap
    // io_map_base points to the offset within the TSS where the bitmap starts
    tss->io_map_base = TSS_BASE_SIZE;
    memset(tss->io_bitmap, 0xFF, IO_BITMAP_SIZE);
    tss->io_bitmap_end = 0xFF;

    gdt_set_tss(tss);
    CPU_LOCAL_WRITE(cpu_tss, tss);

    gdtr_t gdtr;
    gdtr.limit = sizeof(gdt) - 1;
    gdtr.base = (uint64_t) &gdt;
    __load_gdt(&gdtr, 0x08, 0x10, 0x30);
}

// Bit = 0: Port allowed, Bit = 1: Port denied
void tss_io_allow_port(tss_t* tss, uint16_t port) {
    if (!tss) return;

    uint16_t byte_offset = port / 8;
    uint8_t bit_offset = port % 8;

    if (byte_offset < IO_BITMAP_SIZE) {
        // Clear the bit to allow access
        tss->io_bitmap[byte_offset] &= ~(1 << bit_offset);
    }
}

void tss_io_deny_port(tss_t* tss, uint16_t port) {
    if (!tss) return;

    uint16_t byte_offset = port / 8;
    uint8_t bit_offset = port % 8;

    if (byte_offset < IO_BITMAP_SIZE) {
        tss->io_bitmap[byte_offset] |= (1 << bit_offset);
    }
}

void tss_io_allow_port_range(tss_t* tss, uint16_t start_port, uint16_t end_port) {
    if (!tss) return;

    for (uint16_t port = start_port; port <= end_port; port++) {
        tss_io_allow_port(tss, port);
        if (port == 0xFFFF) break;
    }
}

void tss_io_deny_port_range(tss_t* tss, uint16_t start_port, uint16_t end_port) {
    if (!tss) return;

    for (uint16_t port = start_port; port <= end_port; port++) {
        tss_io_deny_port(tss, port);
        if (port == 0xFFFF) break;
    }
}

bool tss_io_is_port_allowed(tss_t* tss, uint16_t port) {
    if (!tss) return false;

    uint16_t byte_offset = port / 8;
    uint8_t bit_offset = port % 8;

    if (byte_offset >= IO_BITMAP_SIZE) {
        return false;
    }

    return (tss->io_bitmap[byte_offset] & (1 << bit_offset)) == 0;
}

void tss_io_clear(tss_t* tss) {
    memset(tss->io_bitmap, 0xFF, IO_BITMAP_SIZE);
}
