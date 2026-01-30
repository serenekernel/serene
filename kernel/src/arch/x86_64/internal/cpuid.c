#include <arch/internal/cpuid.h>
#include <stdbool.h>
#include <stdint.h>

[[nodiscard]] uint32_t __cpuid(cpuid_leaf_t leaf, uint32_t subleaf, cpuid_reg_t reg) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(leaf), "c"(subleaf));

    switch(reg) {
        case CPUID_EAX: return eax;
        case CPUID_EBX: return ebx;
        case CPUID_ECX: return ecx;
        case CPUID_EDX: return edx;
    }
    __builtin_unreachable();
}

[[nodiscard]] uint32_t __cpuid_get_feature_value(cpuid_feature_t feature) {
    return __cpuid((cpuid_leaf_t) feature.leaf, feature.subleaf, feature.reg) & feature.mask;
}
