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

// extended feature enable register
#define IA32_EFER 0xC0000080

// syscall stuff
#define IA32_STAR   0xC0000081
#define IA32_LSTAR  0xC0000082
#define IA32_CSTAR  0xC0000083
#define IA32_SFMASK 0xC0000084


[[nodiscard]] uint64_t __rdmsr(uint32_t msr);
void __wrmsr(uint32_t msr, uint64_t value);
