#pragma once
#include <arch/memory.h>
#include <stdint.h>

#define ALIGN_UP(x, align) ((((uintptr_t) (x)) + ((align) - 1)) & ~((uintptr_t) ((align) - 1)))
#define ALIGN_DOWN(x, align) (((uintptr_t) (x)) & ~((uintptr_t) ((align) - 1)))

typedef uintptr_t phys_addr_t;
typedef uintptr_t virt_addr_t;

typedef enum {
    PAGE_SIZE_DEFAULT = ARCH_PAGE_SIZE_DEFAULT,
    PAGE_SIZE_SMALL = ARCH_PAGE_SIZE_SMALL,
    PAGE_SIZE_LARGE = ARCH_PAGE_SIZE_LARGE,
    PAGE_SIZE_HUGE = ARCH_PAGE_SIZE_HUGE
} page_size_t;

typedef enum {
    VM_PROTECTION_READ_ONLY,
    VM_PROTECTION_READ_WRITE,
    VM_PROTECTION_READ_EXECUTE,
    VM_PROTECTION_READ_WRITE_EXECUTE,
} vm_protection_t;

typedef struct {
    bool present    : 1;
    bool readable   : 1;
    bool write      : 1;
    bool execute    : 1;
    bool global     : 1;
    bool __reserved : 1;
} vm_protection_flags_t;

static_assert(sizeof(vm_protection_flags_t) == sizeof(uint8_t), "vm_protection_flags_t must be 1 byte some dumbass (me) broke it");

typedef enum {
    VM_ACCESS_KERNEL,
    VM_ACCESS_USER,
} vm_access_t;

typedef enum {
    VM_CACHE_NORMAL,
    VM_CACHE_DISABLE,
    VM_CACHE_WRITE_THROUGH,
    VM_CACHE_WRITE_COMBINE
} vm_cache_t;

vm_protection_flags_t convert_vm_protection_raw(vm_protection_t protection, bool present, bool global);
vm_protection_flags_t convert_vm_protection_basic(vm_protection_t protection);

const char* limine_memmap_type_to_str(uint64_t type);
