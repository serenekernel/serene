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

vm_protection_flags_t convert_vm_protection_raw(vm_protection_t protection, bool present, bool global) {
    switch(protection) {
        case VM_PROTECTION_READ_ONLY:          return (vm_protection_flags_t) { .present = present, .readable = true, .write = false, .execute = false, .global = global };
        case VM_PROTECTION_READ_WRITE:         return (vm_protection_flags_t) { .present = present, .readable = true, .write = true, .execute = false, .global = global };
        case VM_PROTECTION_READ_EXECUTE:       return (vm_protection_flags_t) { .present = present, .readable = true, .write = false, .execute = true, .global = global };
        case VM_PROTECTION_READ_WRITE_EXECUTE: return (vm_protection_flags_t) { .present = present, .readable = true, .write = true, .execute = true, .global = global };
    }
    __builtin_unreachable();
}

vm_protection_flags_t convert_vm_protection_basic(vm_protection_t protection) {
    return convert_vm_protection_raw(protection, true, false);
}
