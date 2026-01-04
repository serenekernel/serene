#include <arch/cpuid.h>
#include <stdbool.h>
#include <stdint.h>

[[nodiscard]] uint32_t __cpuid(cpuid_leaf_t leaf, uint32_t subleaf, cpuid_reg_t reg) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("xchgq  %%rbx, %q1\n" "cpuid\n" "xchgq  %%rbx,%q1" : "=a"(eax), "=r"(ebx), "=c"(ecx), "=d"(edx) : "0"(leaf), "2"(subleaf));

    switch(reg) {
        case CPUID_EAX: return eax;
        case CPUID_EBX: return ebx;
        case CPUID_ECX: return ecx;
        case CPUID_EDX: return edx;
    }
    __builtin_unreachable();
}

void __cpuid_dump_info(void);
