#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    CPUID_EAX = 0,
    CPUID_EBX = 1,
    CPUID_ECX = 2,
    CPUID_EDX = 3
} cpuid_reg_t;

typedef struct {
    uint32_t leaf;
    uint32_t subleaf;
    cpuid_reg_t reg;
    uint32_t mask;
} cpuid_feature_t;

typedef enum {
    CPUID_VENDOR_ID = 0x0,
    CPUID_GET_FEATURES = 0x1,
    CPUID_GET_EXTENDED_FEATURES = 0x7,
    CPUID_EXTENDED_PROCESSOR_INFO = 0x80000001
} cpuid_leaf_t;

#define CPUID_FEATURE_DEFINE(name, __leaf, __subleaf, __reg, __bit) static cpuid_feature_t CPUID_FEATURE_##name = { .leaf = __leaf, .subleaf = __subleaf, .reg = __reg, .mask = (1 << __bit) };

CPUID_FEATURE_DEFINE(X2APIC, CPUID_GET_FEATURES, 0, CPUID_ECX, 21);
CPUID_FEATURE_DEFINE(PAT, CPUID_GET_FEATURES, 0, CPUID_EDX, 16);
CPUID_FEATURE_DEFINE(FXSR, CPUID_GET_FEATURES, 0, CPUID_EDX, 24);
CPUID_FEATURE_DEFINE(XSAVE, CPUID_GET_FEATURES, 0, CPUID_ECX, 26);
CPUID_FEATURE_DEFINE(OSXSAVE, CPUID_GET_FEATURES, 0, CPUID_ECX, 27);
CPUID_FEATURE_DEFINE(AVX, CPUID_GET_FEATURES, 0, CPUID_ECX, 28);
CPUID_FEATURE_DEFINE(AVX512, CPUID_GET_EXTENDED_FEATURES, 0, CPUID_EBX, 16);
CPUID_FEATURE_DEFINE(SMAP, CPUID_GET_EXTENDED_FEATURES, 0, CPUID_EBX, 20);
CPUID_FEATURE_DEFINE(SMEP, CPUID_GET_EXTENDED_FEATURES, 0, CPUID_EBX, 7);
CPUID_FEATURE_DEFINE(UMIP, CPUID_GET_EXTENDED_FEATURES, 0, CPUID_ECX, 2);
CPUID_FEATURE_DEFINE(FRED, CPUID_GET_EXTENDED_FEATURES, 1, CPUID_EAX, 17);
CPUID_FEATURE_DEFINE(LKGS, CPUID_GET_EXTENDED_FEATURES, 1, CPUID_EAX, 18);

[[nodiscard]] bool __cpuid_is_feature_supported(cpuid_feature_t feature);
[[nodiscard]] uint32_t __cpuid_get_feature_value(cpuid_feature_t feature);
[[nodiscard]] uint32_t __cpuid(cpuid_leaf_t leaf, uint32_t subleaf, cpuid_reg_t reg);

[[nodiscard]] const char* __cpuid_get_vendor_string();
[[nodiscard]] const char* __cpuid_get_name_string();
