#include "common/memory.h"
#include "memory/vmm.h"
#include <assert.h>
#include <common/acpi.h>
#include <common/requests.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t acpi_revision;
    uint8_t number_of_tables;
    acpi_sdt_t* entries[];
} acpi_tables_t;

acpi_tables_t* g_tables = nullptr;

bool acpi_checksum(uint8_t* data, size_t length) {
    uint8_t sum = 0;
    for(size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    return (sum == 0);
}

void acpi_init(void) {
    acpi_xsdp_t* xsdp = rsdp_request.response->address;
    assert(xsdp != NULL && "RSDP address is null");
    assert(strncmp(xsdp->signature, ACPI_SIGNATURE_RSDP, 8) == 0 && "RSDP signature invalid");
    assert(acpi_checksum((uint8_t*) xsdp, sizeof(acpi_rsdp_t)) && "RSDP checksum invalid");
    printf("RSDP revision: %d\n", xsdp->revision);

    uint32_t xsdp_size = (xsdp->revision >= 2) ? sizeof(acpi_xsdp_t) : sizeof(acpi_rsdp_t);
    uint32_t length = 0;
    if(xsdp->revision >= 2) {
        acpi_xsdt_t* xsdt = (acpi_xsdt_t*) TO_HHDM(xsdp->xsdt_address);
        length = xsdt->header.length;
        assert(strncmp(xsdt->header.signature, ACPI_SIGNATURE_XSDT, 4) == 0 && "XSDT signature invalid");
        assert(acpi_checksum((uint8_t*) xsdt, xsdt->header.length) && "XSDT checksum invalid");
    } else {
        acpi_rsdt_t* rsdt = (acpi_rsdt_t*) TO_HHDM(xsdp->__rsdt_address);
        length = rsdt->header.length;
        assert(strncmp(rsdt->header.signature, ACPI_SIGNATURE_RSDT, 4) == 0 && "RSDT signature invalid");
        assert(acpi_checksum((uint8_t*) rsdt, rsdt->header.length) && "RSDT checksum invalid");
    }

    uint8_t entry_size = (xsdp->revision >= 2) ? sizeof(uint64_t) : sizeof(uint32_t);
    uint32_t number_of_tables = (length - sizeof(acpi_sdt_t)) / entry_size;
    printf("%u %u %u\n", length, xsdp_size, entry_size);
    printf("ACPI has %u tables\n", number_of_tables);
    printf("%u\n", sizeof(acpi_tables_t) + (sizeof(uintptr_t) * number_of_tables));

    acpi_tables_t* tables = (acpi_tables_t*)vmm_alloc_object(&kernel_allocator, sizeof(acpi_tables_t) + (sizeof(uintptr_t) * number_of_tables));
    tables->acpi_revision = xsdp->revision;
    tables->number_of_tables = number_of_tables;
    g_tables = tables;

    for(size_t i = 0; i < number_of_tables; i++) {
        uintptr_t entry_addr = (xsdp->revision >= 2)
                                   ? ((acpi_xsdt_t*) TO_HHDM(xsdp->xsdt_address))->entries[i]
                                   : ((acpi_rsdt_t*) TO_HHDM(xsdp->__rsdt_address))->entries[i];
        tables->entries[i] = (acpi_sdt_t*) TO_HHDM(entry_addr);
    }

    for(size_t i = 0; i < number_of_tables; i++) {
        acpi_sdt_t* entry = tables->entries[i];
        printf("ACPI Table: %.4s @ 0x%lx\n", entry->signature, (uintptr_t) entry);
    }
}

acpi_sdt_t* acpi_find_table(const char* signature) {
    for(size_t i = 0; i < g_tables->number_of_tables; i++) {
        acpi_sdt_t* entry = g_tables->entries[i];
        if(strncmp(entry->signature, signature, 4) == 0) {
            return entry;
        }
    }

    assert(false && "ACPI table not found");
    return NULL;
}
