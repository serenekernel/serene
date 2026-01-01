#include "arch/hardware/lapic.h"
#include "common/interrupts.h"
#include "common/io.h"
#include "common/memory.h"
#include "uacpi/internal/tables.h"
#include "uacpi/status.h"

#include <arch/gdt.h>
#include <arch/interrupts.h>
#include <common/arch.h>
#include <common/requests.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdio.h>

const char* arch_get_name(void) {
    return "x86_64";
}

[[noreturn]] void arch_die(void) {
    for(;;) {
        __asm__ volatile("cli");
        __asm__ volatile("hlt");
    }
}

void arch_memory_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

void arch_pause() {
    __asm__ volatile("pause" ::: "memory");
}

uacpi_iteration_decision parse_madt(uacpi_handle handle, struct acpi_entry_hdr* hdr) {
    (void) handle;
    if(hdr->type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
        struct acpi_madt_lapic* mhdr = (struct acpi_madt_lapic*) (hdr);
        printf("MADT/lapic 0x%llx (%d) %d | %d %d 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->uid, mhdr->id, mhdr->flags);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
        struct acpi_madt_ioapic* mhdr = (struct acpi_madt_ioapic*) (hdr);
        printf("MADT/ioapic 0x%llx (%d) %d | %d 0x%llx 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->id, mhdr->address, mhdr->gsi_base);
        ioapic_init(mhdr->id, mhdr->address);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
        struct acpi_madt_interrupt_source_override* mhdr = (struct acpi_madt_interrupt_source_override*) (hdr);
        printf("MADT/iso 0x%llx (%d) %d | %d %d 0x%llx 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->bus, mhdr->source, mhdr->gsi, mhdr->flags);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_LAPIC_NMI) {
        struct acpi_madt_lapic_nmi* mhdr = (struct acpi_madt_lapic_nmi*) (hdr);
        printf("MADT/lapicnmi 0x%llx (%d) %d | %d %d 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->uid, mhdr->flags, mhdr->lint);
    } else {
        printf("MADT/unknown 0x%llx (%d) %d\n", hdr, hdr->type, hdr->length);
    }

    return UACPI_ITERATION_DECISION_CONTINUE;
}


void setup_memory() {
    pmm_init();

    phys_addr_t highest_phys_address = 0;
    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* entry = memmap_request.response->entries[i];
        if(entry->base + entry->length > highest_phys_address) {
            highest_phys_address = entry->base + entry->length;
        }
    }

    virt_addr_t virtual_start = (virt_addr_t) highest_phys_address + hhdm_request.response->offset;

    vmm_init(&kernel_allocator, virtual_start, virtual_start + 0x80000000);
    vm_paging_bsp_init(&kernel_allocator);

    vm_map_kernel();
    printf("we pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("we didn't die\n");
}

void setup_arch() {
    setup_gdt();
    printf("GDT INIT OK!\n");

    setup_idt_bsp();
    printf("IDT INIT OK!\n");
    if(rsdp_request.response == NULL) {
        printf("ACPI init NOT okay\n");
    } else {
        phys_addr_t phys = pmm_alloc_page();
        virt_addr_t virt = vmm_alloc(&kernel_allocator, 1);
        vm_map_page(&kernel_allocator, virt, phys, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, convert_vm_protection_basic(VM_PROTECTION_READ_WRITE));
        if(uacpi_setup_early_table_access((void*) virt, 1 * PAGE_SIZE_DEFAULT) != UACPI_STATUS_OK) {
            printf("uACPI init VERY NOT okay!\n");
            arch_die();
        }
        printf("uACPI INIT OK!\n");
    }
    lapic_init_bsp();
    printf("LAPIC INIT OK!\n");
}

void setup_uacpi() {
    uacpi_table tbl;
    uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &tbl);
    uacpi_for_each_subtable(tbl.hdr, sizeof(struct acpi_madt), parse_madt, NULL);

    printf("IOAPIC INIT OK!\n");
}

void ps2_test(interrupt_frame*) {
    if((port_read_u8(0x64) & 1) == 1) {
        uint8_t scancode = port_read_u8(0x60);
        printf("Scancode: 0x%02x\n", scancode);
    }
}

void arch_init_bsp() {
    setup_memory();
    setup_arch();
    setup_uacpi();
    register_interrupt_handler(0x21, ps2_test);
    enable_interrupts();
    printf("...\n");
    while(((port_read_u8(0x64) >> 0) & 1) == 1) port_read_u8(0x60);

    while(1) {
        arch_wait_for_interrupt();
    }
}

void arch_init_ap() {
    vm_paging_ap_init(&kernel_allocator);
    printf("ap paging pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("ap didn't kill itself\n");

    setup_gdt();
    setup_idt_ap();

    while(1) {
        arch_wait_for_interrupt();
    }
}

void arch_wait_for_interrupt(void) {
    __asm__ volatile("hlt");
}

uint32_t arch_get_core_id() {
    return lapic_get_id();
}

bool arch_is_bsp() {
    return lapic_is_bsp();
}

uint64_t arch_get_flags() {
    uint64_t rflags;
    __asm__ volatile("pushfq\n" "popq %0\n" : "=r"(rflags));
    return rflags;
}

void arch_set_flags(uint64_t flags) {
    __asm__ volatile("pushq %0\n" "popfq\n" : : "r"(flags));
}
