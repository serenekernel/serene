#include "common/io.h"
#include "memory/memory.h"
#include <common/acpi.h>
#include "memory/vmm.h"
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

io_apic_iso_t io_apic_isos[32];
size_t io_apic_iso_count = 0;

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

void ioapic_add_iso(uint8_t bus, uint8_t source, uint32_t gsi, uint16_t flags) {
    assert(io_apic_iso_count < sizeof(io_apic_isos) / sizeof(io_apic_isos[0]) && "Maximum ISO entries reached");
    io_apic_isos[io_apic_iso_count].bus = bus;
    io_apic_isos[io_apic_iso_count].source = source;
    io_apic_isos[io_apic_iso_count].gsi = gsi;
    io_apic_isos[io_apic_iso_count].flags = flags;
    io_apic_iso_count++;
}

void ioapic_map_irq(io_apic_t* ioapic, uint8_t irq, uint8_t vector, uint8_t destination) {
    uint64_t redirect = vector;
    redirect |= IOAPIC_DELIVERY_FIXED;
    redirect |= ((uint64_t) destination << IOAPIC_DEST_SHIFT);
    printf("Mapping IRQ %u to vector 0x%02X on destination 0x%02X\n", irq, vector, destination);
    ioapic_set_entry(ioapic, irq, redirect);
}

void ioapic_mask_irq(uint8_t irq) {
    uint8_t actual_irq = irq;
    for(size_t i = 0; i < io_apic_iso_count; i++) {
        if(io_apic_isos[i].source == irq) {
            actual_irq = io_apic_isos[i].gsi;
            break;
        }
    }

    io_apic_t* target_ioapic = NULL;
    for(size_t i = 0; i < ioapic_count; i++) {
        io_apic_t* ioapic = &ioapics[i];
        if(actual_irq < ioapic->max_redirection_entry) {
            target_ioapic = ioapic;
            break;
        } else {
            actual_irq -= ioapic->max_redirection_entry;
        }
    }

    if(target_ioapic) {
        uint32_t low = ioapic_read(target_ioapic, IOAPIC_REG_REDTBL_BASE + (actual_irq * 2));
        uint32_t high = ioapic_read(target_ioapic, IOAPIC_REG_REDTBL_BASE + (actual_irq * 2) + 1);
        uint64_t entry = ((uint64_t) high << 32) | low;
        entry |= IOAPIC_MASKED;
        ioapic_set_entry(target_ioapic, actual_irq, entry);
    } else {
        printf("ioapic_mask_irq: could not find target ioapic for IRQ %u\n", irq);
    }
}

void ioapic_unmask_irq(uint8_t irq) {
    uint8_t actual_irq = irq;
    for(size_t i = 0; i < io_apic_iso_count; i++) {
        if(io_apic_isos[i].source == irq) {
            actual_irq = io_apic_isos[i].gsi;
            break;
        }
    }

    io_apic_t* target_ioapic = NULL;
    for(size_t i = 0; i < ioapic_count; i++) {
        io_apic_t* ioapic = &ioapics[i];
        if(actual_irq < ioapic->max_redirection_entry) {
            target_ioapic = ioapic;
            break;
        } else {
            actual_irq -= ioapic->max_redirection_entry;
        }
    }

    if(target_ioapic) {
        uint32_t low = ioapic_read(target_ioapic, IOAPIC_REG_REDTBL_BASE + (actual_irq * 2));
        uint32_t high = ioapic_read(target_ioapic, IOAPIC_REG_REDTBL_BASE + (actual_irq * 2) + 1);
        uint64_t entry = ((uint64_t) high << 32) | low;
        entry &= ~IOAPIC_MASKED;
        ioapic_set_entry(target_ioapic, actual_irq, entry);
    } else {
        printf("ioapic_unmask_irq: could not find target ioapic for IRQ %u\n", irq);
    }
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
}

void dump_madt_entry(acpi_madt_entry_hdr_t* hdr) {
    if(hdr->type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
        acpi_madt_lapic_t* mhdr = (acpi_madt_lapic_t*) (hdr);
        printf("MADT/lapic 0x%llx (%d) %d | %d %d 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->acpi_id, mhdr->apic_id, mhdr->flags);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
        acpi_madt_ioapic_t* mhdr = (acpi_madt_ioapic_t*) (hdr);
        printf("MADT/ioapic 0x%llx (%d) %d | %d 0x%llx 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->id, mhdr->address, mhdr->gsi_base);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
        acpi_madt_interrupt_source_override_t* mhdr = (acpi_madt_interrupt_source_override_t*) (hdr);
        printf("MADT/iso 0x%llx (%d) %d | %d %d 0x%llx 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->bus, mhdr->source, mhdr->gsi, mhdr->flags);
    } else if(hdr->type == ACPI_MADT_ENTRY_TYPE_LAPIC_NMI) {
        acpi_madt_lapic_nmi_t* mhdr = (acpi_madt_lapic_nmi_t*) (hdr);
        printf("MADT/lapicnmi 0x%llx (%d) %d | %d %d 0x%llx\n", hdr, hdr->type, hdr->length, mhdr->acpi_id, mhdr->flags, mhdr->lint);
    } else {
        printf("MADT/unknown 0x%llx (%d) %d\n", hdr, hdr->type, hdr->length);
    }
}

void madt_first_pass() {
    acpi_madt_t* madt = (acpi_madt_t*)acpi_find_table(ACPI_MADT_SIGNATURE);
    printf("MADT first pass\n");
    for(size_t offset = sizeof(acpi_madt_t); offset < madt->header.length;) {
        acpi_madt_entry_hdr_t* entry = (acpi_madt_entry_hdr_t*) ((uintptr_t) madt + offset);
        dump_madt_entry(entry);

        if(entry->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
            acpi_madt_ioapic_t* ioapic_entry = (acpi_madt_ioapic_t*) entry;
            ioapic_init(ioapic_entry->id, ioapic_entry->address);
        }

        offset += entry->length;
    }
}

void madt_second_pass() {
    acpi_madt_t* madt = (acpi_madt_t*)acpi_find_table(ACPI_MADT_SIGNATURE);
    printf("MADT second pass\n");
    for(size_t offset = sizeof(acpi_madt_t); offset < madt->header.length;) {
        acpi_madt_entry_hdr_t* entry = (acpi_madt_entry_hdr_t*) ((uintptr_t) madt + offset);
        // dump_madt_entry(entry);
        if(entry->type == ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
            acpi_madt_interrupt_source_override_t* iso_entry = (acpi_madt_interrupt_source_override_t*) entry;
            if(iso_entry->source != iso_entry->gsi) {
                printf("ISO: IRQ %d -> GSI %d\n", iso_entry->source, iso_entry->gsi);
            }

        }

        offset += entry->length;
    }
}

void ioapic_setup() {
    acpi_madt_t* madt = (acpi_madt_t*)acpi_find_table(ACPI_MADT_SIGNATURE);
    madt_first_pass();
    madt_second_pass();

    if(ioapic_count > 0) {
        // map timer 
        ioapic_map_irq(&ioapics[0], 0, 0x20, lapic_get_id());
        ioapic_unmask_irq(0);
        
        // map ps2 keyboard
        ioapic_map_irq(&ioapics[0], 1, 0x21, lapic_get_id());
        ioapic_unmask_irq(1);
    }

    printf("IOAPIC INIT OK!\n");
}
