#include <common/memory.h>
#include <limine.h>

const char* limine_memmap_type_to_str(uint64_t type) {
    switch(type) {
        case LIMINE_MEMMAP_USABLE:                 return "usable";
        case LIMINE_MEMMAP_RESERVED:               return "reserved";
        case LIMINE_MEMMAP_ACPI_RECLAIMABLE:       return "acpireclaim";
        case LIMINE_MEMMAP_ACPI_NVS:               return "acpinvs";
        case LIMINE_MEMMAP_BAD_MEMORY:             return "badmem";
        case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE: return "ldr reclaim";
        case LIMINE_MEMMAP_EXECUTABLE_AND_MODULES: return "exec & modules";
        case LIMINE_MEMMAP_FRAMEBUFFER:            return "fb";
        case LIMINE_MEMMAP_ACPI_TABLES:            return "acpitbl";
        default:                                   return "unknown";
    }
}

vm_flags_data_t convert_vm_flags(vm_flags_t flags) {
    bool present = !(flags & VM_NON_PRESENT);
    bool global = (flags & VM_GLOBAL) != 0;
    bool write = (flags & VM_READ_WRITE) != 0;
    bool execute = (flags & VM_EXECUTE) != 0;

    return (vm_flags_data_t) {
        .present = present,
        .readable = true,
        .write = write,
        .execute = execute,
        .global = global,
        .__reserved = false,
    };
}
