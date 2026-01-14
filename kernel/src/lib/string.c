#include "memory/memory.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <common/interrupts.h>
#include <memory/vmm.h>

size_t strlen(const char* s) {
    size_t len = 0;
    while(s[len] != '\0') {
        len++;
    }
    return len;
}

void* memcpy(void* restrict dest, const void* restrict src, size_t n) {
    uint8_t* restrict pdest = (uint8_t* restrict) dest;
    const uint8_t* restrict psrc = (const uint8_t* restrict) src;

    for(size_t i = 0; i < n; i++) {
        pdest[i] = psrc[i];
    }

    return dest;
}

void* memset(void* s, int c, size_t n) {
    uint8_t* p = (uint8_t*) s;

    for(size_t i = 0; i < n; i++) {
        p[i] = (uint8_t) c;
    }

    return s;
}

void* memmove(void* dest, const void* src, size_t n) {
    uint8_t* pdest = (uint8_t*) dest;
    const uint8_t* psrc = (const uint8_t*) src;

    if(src > dest) {
        for(size_t i = 0; i < n; i++) {
            pdest[i] = psrc[i];
        }
    } else if(src < dest) {
        for(size_t i = n; i > 0; i--) {
            pdest[i - 1] = psrc[i - 1];
        }
    }

    return dest;
}

int memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = (const uint8_t*) s1;
    const uint8_t* p2 = (const uint8_t*) s2;

    for(size_t i = 0; i < n; i++) {
        if(p1[i] != p2[i]) {
            return p1[i] < p2[i] ? -1 : 1;
        }
    }

    return 0;
}

int strcmp(const char* s1, const char* s2) {
    while(*s1 != '\0' && *s2 != '\0') {
        if(*s1 != *s2) {
            return (*s1 < *s2) ? -1 : 1;
        }
        s1++;
        s2++;
    }

    if(*s1 == '\0' && *s2 == '\0') {
        return 0;
    } else if(*s1 == '\0') {
        return -1;
    } else {
        return 1;
    }
}

int strncmp(const char* s1, const char* s2, size_t n) {
    size_t i = 0;

    while(i < n) {
        unsigned char c1 = (unsigned char) s1[i];
        unsigned char c2 = (unsigned char) s2[i];

        if(c1 != c2) return c1 - c2;

        if(c1 == '\0') return 0;

        i++;
    }

    return 0;
}

void memcpy_um_um(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t n) {
    bool irq = interrupts_enabled();
    if(irq) disable_interrupts();
    phys_addr_t cr3 = vm_address_space_switch_raw(src_alloc->kernel_paging_structures_base);

    virt_addr_t kernel_buffer = vmm_alloc_kernel_object(&kernel_allocator, n);
    memcpy((void*) kernel_buffer, (void*) src, n);

    vm_address_space_switch_raw(dest_alloc->kernel_paging_structures_base);
    memcpy((void*) dest, (void*) kernel_buffer, n);

    vmm_free(&kernel_allocator, kernel_buffer);

    vm_address_space_switch_raw(cr3);

    if(irq) enable_interrupts();
    return;
}
