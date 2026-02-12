#include <arch/internal/cpuid.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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
[[nodiscard]] bool __cpuid_is_feature_supported(cpuid_feature_t feature) {
    return (__cpuid((cpuid_leaf_t) feature.leaf, feature.subleaf, feature.reg) & feature.mask) != 0;
}


[[nodiscard]] const char* __cpuid_get_vendor_string() {
    static char vendor[13] = { 0 };
    *(uint32_t*) &vendor[0] = __cpuid(CPUID_VENDOR_ID, 0, CPUID_EBX);
    *(uint32_t*) &vendor[4] = __cpuid(CPUID_VENDOR_ID, 0, CPUID_EDX);
    *(uint32_t*) &vendor[8] = __cpuid(CPUID_VENDOR_ID, 0, CPUID_ECX);
    return vendor;
}

[[nodiscard]] const char* __cpuid_get_name_string() {
    uint32_t max_ext_leaf = __cpuid(0x80000000, 0, CPUID_EAX);
    if(max_ext_leaf < 0x80000004) {
        return "Unknown CPU :(";
    }

    static char name[49];

    char* ptr = name;

    for(uint32_t i = 0x80000002; i <= 0x80000004; i++) {
        uint64_t eax = __cpuid((cpuid_leaf_t) i, 0, CPUID_EAX);
        uint64_t ebx = __cpuid((cpuid_leaf_t) i, 0, CPUID_EBX);
        uint64_t ecx = __cpuid((cpuid_leaf_t) i, 0, CPUID_ECX);
        uint64_t edx = __cpuid((cpuid_leaf_t) i, 0, CPUID_EDX);
        memcpy(ptr, &eax, 4);
        memcpy(ptr + 4, &ebx, 4);
        memcpy(ptr + 8, &ecx, 4);
        memcpy(ptr + 12, &edx, 4);
        ptr += 16;
    }

    name[48] = '\0';
    return name;
}
