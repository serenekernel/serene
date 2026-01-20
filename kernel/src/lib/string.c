#include "common/requests.h"

#include <assert.h>
#include <common/arch.h>
#include <common/interrupts.h>
#include <memory/memory.h>
#include <memory/vmm.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

void memcpy_um_um(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t page_count) {
    bool irq = interrupts_enabled();
    if(irq) disable_interrupts();
#ifdef __ARCH_X86_64__
    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t dest_phys = vm_resolve(dest_alloc, dest + i * PAGE_SIZE_DEFAULT);
        assert(dest_phys != 0 && "memcpy_km_um: source address not mapped");
        phys_addr_t src_phys = vm_resolve(src_alloc, src + i * PAGE_SIZE_DEFAULT);
        assert(src_phys != 0 && "memcpy_km_um: destination address not mapped");
        assert(src_phys != 0 && "memcpy_km_um: destination address not writeable");
    }

    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t dest_phys = vm_resolve(dest_alloc, dest + i * PAGE_SIZE_DEFAULT);
        phys_addr_t src_phys = vm_resolve(src_alloc, src + i * PAGE_SIZE_DEFAULT);
        memcpy((void*) TO_HHDM(dest_phys), (void*) TO_HHDM(src_phys), PAGE_SIZE_DEFAULT);
    }
#else
    (void) dest_alloc;
    (void) src_alloc;
    (void) dest;
    (void) src;
    (void) n;
    assert(false); // @todo:
#endif
    if(irq) enable_interrupts();
    return;
}

void memcpy_km_um(vm_allocator_t* dest_alloc, virt_addr_t dest, virt_addr_t src, size_t page_count) {
    bool irq = interrupts_enabled();
    if(irq) disable_interrupts();
#ifdef __ARCH_X86_64__
    // verify all pages are mapped
    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t phys = vm_resolve(dest_alloc, dest + i * PAGE_SIZE_DEFAULT);
        assert(phys != 0 && "memcpy_km_um: destination address not mapped");
    }

    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t phys = vm_resolve(dest_alloc, dest + i * PAGE_SIZE_DEFAULT);
        memcpy((void*) TO_HHDM(phys), (void*) (src + (i * PAGE_SIZE_DEFAULT)), PAGE_SIZE_DEFAULT);
    }
#else
    (void) dest_alloc;
    (void) dest;
    (void) src;
    (void) n;
    assert(false); // @todo:
#endif
    if(irq) enable_interrupts();
    return;
}

void memset_vm(vm_allocator_t* dest_alloc, virt_addr_t dest, int c, size_t page_count) {
    bool irq = interrupts_enabled();
    if(irq) disable_interrupts();

    if(dest_alloc->is_user == false) {
        memset((void*) dest, c, page_count * PAGE_SIZE_DEFAULT);
        if(irq) enable_interrupts();
        return;
    }

#ifdef __ARCH_X86_64__
    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t phys = vm_resolve(dest_alloc, dest + (i * PAGE_SIZE_DEFAULT));
        assert(phys != 0 && "memcpy_km_um: destination address not mapped");
    }

    for(size_t i = 0; i < page_count; i++) {
        phys_addr_t phys = vm_resolve(dest_alloc, dest + (i * PAGE_SIZE_DEFAULT));
        memset((void*) TO_HHDM(phys), c, PAGE_SIZE_DEFAULT);
    }
#else
    (void) dest_alloc;
    (void) dest;
    (void) src;
    (void) n;
    assert(false); // @todo:
#endif
    if(irq) enable_interrupts();
    return;
}

void memcpy_um_um_unaligned(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t length) {
    virt_addr_t src_page_aligned = ALIGN_DOWN(src, PAGE_SIZE_DEFAULT);
    virt_addr_t dest_page_aligned = ALIGN_DOWN(dest, PAGE_SIZE_DEFAULT);
    size_t src_offset = src - src_page_aligned;
    size_t dest_offset = dest - dest_page_aligned;

    for(size_t i = 0; i < length; i++) {
        size_t src_page = (src_offset + i) / PAGE_SIZE_DEFAULT;
        size_t src_page_offset = (src_offset + i) % PAGE_SIZE_DEFAULT;
        size_t dest_page = (dest_offset + i) / PAGE_SIZE_DEFAULT;
        size_t dest_page_offset = (dest_offset + i) % PAGE_SIZE_DEFAULT;

        phys_addr_t src_phys = vm_resolve(src_alloc, src_page_aligned + src_page * PAGE_SIZE_DEFAULT);
        phys_addr_t dest_phys = vm_resolve(dest_alloc, dest_page_aligned + dest_page * PAGE_SIZE_DEFAULT);

        uint8_t* src_byte = (uint8_t*) TO_HHDM(src_phys + src_page_offset);
        uint8_t* dest_byte = (uint8_t*) TO_HHDM(dest_phys + dest_page_offset);
        *dest_byte = *src_byte;
    }
}
