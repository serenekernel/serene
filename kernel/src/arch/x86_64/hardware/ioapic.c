#include "common/io.h"
#include "common/memory.h"
#include "memory/vmm.h"
#include "uacpi/acpi.h"
#include "uacpi/tables.h"

#include <arch/hardware/lapic.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
// I/O APIC registers

#define IOAPIC_REG_ID 0x00
#define IOAPIC_REG_VER 0x01
#define IOAPIC_REG_ARBITRATION 0x02
#define IOAPIC_REG_REDTBL_BASE 0x10

// I/O APIC Redirection Entry flags
#define IOAPIC_DEST_SHIFT 56
#define IOAPIC_DEST_MASK 0xFF00000000000000
#define IOAPIC_MASKED (1 << 16)
#define IOAPIC_TRIGGER_LEVEL (1 << 15)
#define IOAPIC_REMOTE_IRR (1 << 14)
#define IOAPIC_PIN_POLARITY (1 << 13)
#define IOAPIC_DELIVERY_STATUS (1 << 12)
#define IOAPIC_DEST_MODE_LOG (1 << 11)
#define IOAPIC_DELIVERY_MODE (0x700)
#define IOAPIC_VECTOR_MASK 0xFF

// Delivery modes
#define IOAPIC_DELIVERY_FIXED 0x000
#define IOAPIC_DELIVERY_LOWEST 0x100
#define IOAPIC_DELIVERY_SMI 0x200
#define IOAPIC_DELIVERY_NMI 0x400
#define IOAPIC_DELIVERY_INIT 0x500
#define IOAPIC_DELIVERY_EXTINT 0x700

// todo: im so lazy
#define MAX_IOAPICS 8
io_apic_t ioapics[MAX_IOAPICS];
size_t ioapic_count = 0;

static uint32_t ioapic_read(io_apic_t* ioapic, uint32_t reg) {
    mmio_write_u32(ioapic->mmio, reg);
    return mmio_read_u32(ioapic->mmio + (4 * 4));
}

static void ioapic_write(io_apic_t* ioapic, uint32_t reg, uint32_t value) {
    mmio_write_u32(ioapic->mmio, reg);
    mmio_write_u32(ioapic->mmio + (4 * 4), value);
}

static void ioapic_set_entry(io_apic_t* ioapic, uint8_t index, uint64_t data) {
    ioapic_write(ioapic, IOAPIC_REG_REDTBL_BASE + index * 2, (uint32_t) data);
    ioapic_write(ioapic, IOAPIC_REG_REDTBL_BASE + index * 2 + 1, (uint32_t) (data >> 32));
}

void ioapic_map_irq(io_apic_t* ioapic, uint8_t irq, uint8_t vector, uint8_t destination) {
    uint64_t redirect = vector;
    redirect |= IOAPIC_DELIVERY_FIXED;
    redirect |= ((uint64_t) destination << IOAPIC_DEST_SHIFT);
    printf("Mapping IRQ %u to vector 0x%02X on destination 0x%02X\n", irq, vector, destination);
    ioapic_set_entry(ioapic, irq, redirect);
}


void ioapic_init(uint32_t id, phys_addr_t phys_addr) {
    assert(lapic_is_bsp() && "ioapic_init should only be called on BSP");
    if(ioapic_count >= MAX_IOAPICS) {
        printf("ioapic_init: maximum ioapics reached\n");
        return;
    }

    virt_addr_t mmio_virt = vmm_alloc(&kernel_allocator, 1);
    vm_map_page(&kernel_allocator, mmio_virt, phys_addr, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE);

    ioapic_count++;
    io_apic_t* ioapic = &ioapics[ioapic_count - 1];
    ioapic->id = id;
    ioapic->mmio = mmio_virt;
    uint32_t ver = ioapic_read(ioapic, IOAPIC_REG_VER);
    ioapic->max_redirection_entry = ((ver >> 16) & 0xFF) + 1;

    printf("ioapic_init: initialized ioapic id %u at phys 0x%llx virt 0x%llx ver: 0x%08x, redirection entries: %u\n", id, phys_addr, mmio_virt, ver & 0xff, ioapic->max_redirection_entry);
    for(uint32_t i = 0; i < ioapic->max_redirection_entry; i++) {
        ioapic_set_entry(ioapic, i, IOAPIC_MASKED);
    }

    ioapic_map_irq(ioapic, 1, 0x21, lapic_get_id());
}

void dump_madt_entry(struct acpi_entry_hdr* hdr) {
    if(hdr->type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
        struct acpi_madt_lapic* mhdr = (struct acpi_madt_lapic*) (hdr);
        printf("MADT/lapic 0x%llx (%d) %d | %d %d 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->uid, mhdr->id, mhdr->flags);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
        struct acpi_madt_ioapic* mhdr = (struct acpi_madt_ioapic*) (hdr);
        printf("MADT/ioapic 0x%llx (%d) %d | %d 0x%llx 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->id, mhdr->address, mhdr->gsi_base);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
        struct acpi_madt_interrupt_source_override* mhdr = (struct acpi_madt_interrupt_source_override*) (hdr);
        printf("MADT/iso 0x%llx (%d) %d | %d %d 0x%llx 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->bus, mhdr->source, mhdr->gsi, mhdr->flags);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_LAPIC_NMI) {
        struct acpi_madt_lapic_nmi* mhdr = (struct acpi_madt_lapic_nmi*) (hdr);
        printf("MADT/lapicnmi 0x%llx (%d) %d | %d %d 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->uid, mhdr->flags, mhdr->lint);
    } else {
        printf("MADT/unknown 0x%llx (%d) %d\n", hdr, hdr->type, hdr->length);
    }
}

uacpi_iteration_decision parse_madt(uacpi_handle handle, struct acpi_entry_hdr* hdr) {
    (void) handle;

    dump_madt_entry(hdr);
    if(hdr->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
        struct acpi_madt_ioapic* mhdr = (struct acpi_madt_ioapic*) (hdr);
        ioapic_init(mhdr->id, mhdr->address);
    }

    return UACPI_ITERATION_DECISION_CONTINUE;
}

void ioapic_setup() {
    uacpi_table tbl;
    uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &tbl);
    uacpi_for_each_subtable(tbl.hdr, sizeof(struct acpi_madt), parse_madt, NULL);

    printf("IOAPIC INIT OK!\n");
}
