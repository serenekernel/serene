#include <assert.h>
#include <common/acpi.h>
#include <common/requests.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ACPI_ENUM_ASDT(asdt, size_of_entry) for(size_t i = 0; i < ((asdt)->header.length - sizeof(acpi_sdt_t)) / (size_of_entry); i++)
#define ACPI_ASDT                                                          \
    acpi_xsdt_t* xsdt = ({                                                 \
        acpi_rsdp_t* rsdp = (acpi_rsdp_t*) rsdp_request.response->address; \
        if(rsdp->revision >= 2) {                                          \
            (acpi_xsdt_t*) TO_HHDM(rsdp->xsdt_address);                    \
        } else {                                                           \
            (acpi_rsdt_t*) TO_HHDM(rsdp->rsdt_address);                    \
        }                                                                  \
    })

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
    if(xsdp->revision >= 2) {
        assert(acpi_checksum((uint8_t*) xsdp, xsdp->length) && "XSDP checksum invalid");

        acpi_xsdt_t* xsdt = (acpi_xsdt_t*) TO_HHDM(xsdp->xsdt_address);

        ACPI_ENUM_ASDT(xsdt, 8) {
            uint64_t entry_addr = xsdt->entries[i];
            acpi_sdt_t* entry = (acpi_sdt_t*) TO_HHDM(entry_addr);
            printf("ACPI Table: %.4s @ 0x%lx\n", entry->signature, (uintptr_t) entry);
        }
    } else {
        acpi_rsdt_t* rsdt = (acpi_rsdt_t*) TO_HHDM(xsdp->__rsdt_address);

        ACPI_ENUM_ASDT(rsdt, 4) {
            uint64_t entry_addr = rsdt->entries[i];
            acpi_sdt_t* entry = (acpi_sdt_t*) TO_HHDM(entry_addr);
            printf("ACPI Table: %.4s @ 0x%lx\n", entry->signature, (uintptr_t) entry);
        }
    }
}


acpi_sdt_t* acpi_find_rsdt(const char* signature) {
    acpi_rsdp_t* rsdp = (acpi_rsdp_t*) rsdp_request.response->address;
    acpi_rsdt_t* rsdt = (acpi_rsdt_t*) TO_HHDM(rsdp->rsdt_address);

    ACPI_ENUM_ASDT(rsdt, 4) {
        uint64_t entry_addr = rsdt->entries[i];
        acpi_sdt_t* entry = (acpi_sdt_t*) TO_HHDM(entry_addr);
        if(strncmp(entry->signature, signature, 4) == 0) {
            return entry;
        }
    }

    return NULL;
}

acpi_sdt_t* acpi_find_xsdt(const char* signature) {
    acpi_xsdp_t* rsdp = (acpi_xsdp_t*) rsdp_request.response->address;
    acpi_xsdt_t* xsdt = (acpi_xsdt_t*) TO_HHDM(rsdp->xsdt_address);

    ACPI_ENUM_ASDT(xsdt, 8) {
        uint64_t entry_addr = xsdt->entries[i];
        acpi_sdt_t* entry = (acpi_sdt_t*) TO_HHDM(entry_addr);
        if(strncmp(entry->signature, signature, 4) == 0) {
            return entry;
        }
    }

    return NULL;
}

acpi_sdt_t* acpi_find_table(const char* signature) {
    acpi_xsdp_t* rsdp = (acpi_xsdp_t*) rsdp_request.response->address;
    acpi_xsdt_t* xsdt = (acpi_xsdt_t*) TO_HHDM(rsdp->xsdt_address);

    if(rsdp->revision >= 2) {
        return acpi_find_xsdt(signature);
    } else {
        return acpi_find_rsdt(signature);
    }

    return NULL;
}
