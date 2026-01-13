#pragma once
#include <stdint.h>

// since uacpi runs in user mode, we don't need much
// but we do need to find the tables and parse the madt & hpet

#define ACPI_SIGNATURE_RSDP "RSD PTR "
#define ACPI_SIGNATURE_RSDT "RSDT"
#define ACPI_SIGNATURE_XSDT "XSDT"
#define ACPI_MADT_SIGNATURE "APIC"

// ACPI header present in all* tables (except RSDP/XSDP)
typedef struct {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed)) acpi_sdt_t;

// ACPI 1.0 RSDP structure
typedef struct {
    char signature[8]; // should be "RSD PTR "
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
} __attribute__((packed)) acpi_rsdp_t;

typedef struct {
    acpi_sdt_t header;
    uint32_t entries[];
} __attribute__((packed)) acpi_rsdt_t;

// ACPI 2.0 XSDP structure
typedef struct {
    char signature[8]; // should be "RSD PTR "
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t __rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed)) acpi_xsdp_t;

typedef struct {
    acpi_sdt_t header;
    uint64_t entries[];
} __attribute__((packed)) acpi_xsdt_t;

// MADT structures
#define ACPI_MADT_ENTRY_TYPE_LAPIC 0
#define ACPI_MADT_ENTRY_TYPE_IOAPIC 1
#define ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE 2
#define ACPI_MADT_ENTRY_TYPE_NMI_SOURCE 3
#define ACPI_MADT_ENTRY_TYPE_LAPIC_NMI 4

typedef struct {
    uint8_t type;
    uint8_t length;
} __attribute__((packed)) acpi_madt_entry_hdr_t;

// ACPI_MADT_ENTRY_TYPE_LAPIC
typedef struct {
    acpi_madt_entry_hdr_t hdr;
    uint8_t acpi_id;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed)) acpi_madt_lapic_t;

// ACPI_MADT_ENTRY_TYPE_IOAPIC
typedef struct {
    acpi_madt_entry_hdr_t hdr;
    uint8_t id;
    uint8_t __rsv0;
    uint32_t address;
    uint32_t gsi_base;
} __attribute__((packed)) acpi_madt_ioapic_t;

// ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE
typedef struct {
    acpi_madt_entry_hdr_t hdr;
    uint8_t bus;
    uint8_t source;
    uint32_t gsi;
    uint16_t flags;
} __attribute__((packed)) acpi_madt_interrupt_source_override_t;

// ACPI_MADT_ENTRY_TYPE_NMI_SOURCE
typedef struct {
    acpi_madt_entry_hdr_t hdr;
    uint16_t flags;
    uint32_t gsi;
} __attribute__((packed)) acpi_madt_nmi_source_t;

// ACPI_MADT_ENTRY_TYPE_LAPIC_NMI
typedef struct {
    acpi_madt_entry_hdr_t hdr;
    uint8_t acpi_id;
    uint16_t flags;
    uint8_t lint;
} __attribute__((packed)) acpi_madt_lapic_nmi_t;

typedef struct {
    acpi_sdt_t header;
    uint32_t lapic_address;
    uint32_t flags;
    // followed by entries
} __attribute__((packed)) acpi_madt_t;


// Helper functions
void acpi_init(void);
acpi_sdt_t* acpi_find_table(const char* signature);