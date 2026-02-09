#include "memory/memory.h"

#include <arch/hardware/fpu.h>
#include <arch/internal/cpuid.h>
#include <assert.h>
#include <common/arch.h>
#include <memory/vmm.h>
#include <stdio.h>
#include <string.h>

size_t g_fpu_area_size;
void (*g_fpu_save)(void* ptr);
void (*g_fpu_load)(void* ptr);

size_t fpu_area_size() {
    return g_fpu_area_size;
}

void fpu_save(void* ptr) {
    g_fpu_save(ptr);
}

void fpu_load(void* ptr) {
    g_fpu_load(ptr);
}

static inline void xsave(void* area) {
    uint32_t eax, edx;
    asm volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0) : "memory");
    asm volatile("xsave (%0)" : : "r"(area), "a"(eax), "d"(edx) : "memory");
}

static inline void xrstor(void* area) {
    uint32_t eax, edx;
    asm volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0) : "memory");
    asm volatile("xrstor (%0)" : : "r"(area), "a"(eax), "d"(edx) : "memory");
}

static inline void fxsave(void* area) {
    asm volatile("fxsave (%0)" : : "r"(area) : "memory");
}

static inline void fxrstor(void* area) {
    asm volatile("fxrstor (%0)" : : "r"(area) : "memory");
}

void fpu_init_bsp() {
    printf("0x%llx\n", __cpuid(1, 0, CPUID_ECX));
    printf("0x%llx\n", __cpuid(1, 0, CPUID_EDX));
    fpu_init_ap();
    if(__cpuid_is_feature_supported(CPUID_FEATURE_XSAVE)) {
        g_fpu_area_size = __cpuid(0x0d, 0, CPUID_ECX);
        printf("using xsave with size 0x%llx\n", g_fpu_area_size);
        assert(g_fpu_area_size > 0);
        g_fpu_save = xsave;
        g_fpu_load = xrstor;
    } else {
        printf("using legacy fxsave\n");
        g_fpu_area_size = 512;
        g_fpu_save = fxsave;
        g_fpu_load = fxrstor;
    }

    return;
}

void fpu_init_ap() {
    assert(__cpuid_is_feature_supported(CPUID_FEATURE_FXSR) && "FXSR not supported on this CPU!");
    // sse & fpu enable
    uint64_t cr0 = __read_cr0();
    cr0 &= ~(1 << 2); // CR0.EM
    cr0 |= 1 << 1; // CR0.MP
    __write_cr0(cr0);

    // mmx and others enable
    uint64_t cr4 = __read_cr4();
    cr4 |= 1 << 9; // CR4.OSFXSR
    cr4 |= 1 << 10; // CR4.OSXMMEXCPT

    if(__cpuid_is_feature_supported(CPUID_FEATURE_XSAVE)) {
        printf("xsave supported\n");
        cr4 |= 1 << 18; // CR4.OSXSAVE
        __write_cr4(cr4);

        uint64_t xcr0 = 0;
        xcr0 |= 1 << 0; // XCR0.X87
        xcr0 |= 1 << 1; // XCR0.SSE
        if(__cpuid_is_feature_supported(CPUID_FEATURE_AVX)) {
            printf("avx supported\n");
            xcr0 |= 1 << 2; // XCR0.AVX
        }
        if(__cpuid_is_feature_supported(CPUID_FEATURE_AVX512)) {
            printf("avx512 supported\n");
            xcr0 |= 1 << 5; // XCR0.opmask
            xcr0 |= 1 << 6; // XCR0.ZMM_Hi256
            xcr0 |= 1 << 7; // XCR0.Hi16_ZMM
        }
        asm volatile("xsetbv" : : "a"(xcr0), "d"(xcr0 >> 32), "c"(0) : "memory");
    } else {
        __write_cr4(cr4);
    }

    return;
}

void* fpu_alloc_area() {
    void* area = (void*) vmm_alloc_object(&kernel_allocator, g_fpu_area_size);
    return area;
}

void fpu_free_area(void* area) {
    vmm_free(&kernel_allocator, (virt_addr_t) area);
}
