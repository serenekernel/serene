#pragma once
#include <stdint.h>

// MSR numbers
#define IA32_APIC_BASE_MSR 0x1B
#define IA32_X2APIC_BASE_MSR 0x800
#define IA32_PAT_MSR 0x277

// APIC Base MSR flags
#define APIC_BASE_BSP (1 << 8)
#define APIC_BASE_ENABLE (1 << 11)
#define APIC_BASE_X2APIC (1 << 10)

// MSRs for segment bases
#define IA32_FS_BASE_MSR 0xC0000100
#define IA32_GS_BASE_MSR 0xC0000101
#define IA32_KERNEL_GS_BASE_MSR 0xC0000102


[[nodiscard]] inline uint64_t __rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t) hi << 32) | lo;
}

inline void __wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t) (value & 0xFFFFFFFF);
    uint32_t hi = (uint32_t) (value >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}
