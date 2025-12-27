#pragma once
#include <arch/memory.h>
#include <stdint.h>

#define ALIGN_UP(x, align) ((((uintptr_t) (x)) + ((align) - 1)) & ~((uintptr_t) ((align) - 1)))
#define ALIGN_DOWN(x, align) (((uintptr_t) (x)) & ~((uintptr_t) ((align) - 1)))

typedef uintptr_t phys_addr_t;
typedef uintptr_t virt_addr_t;
