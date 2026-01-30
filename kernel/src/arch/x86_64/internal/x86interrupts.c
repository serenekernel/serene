#include <arch/hardware/lapic.h>
#include <arch/internal/cpuid.h>
#include <arch/internal/gdt.h>
#include <arch/msr.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/interrupts.h>
#include <common/ipi.h>
#include <memory/memory.h>
#include <memory/vmm.h>
#include <stdint.h>

bool fred_enabled = false;

void setup_idt_bsp();
void setup_idt_ap();

void setup_fred_bsp();
void setup_fred_ap();

void setup_interrupts_bsp() {
    fred_enabled = __cpuid_get_feature_value(CPUID_FEATURE_FRED) != 0;
    printf("fred support: %d\n", fred_enabled);

    if(fred_enabled) {
        setup_fred_bsp();
    } else {
        setup_idt_bsp();
    }
}

void setup_interrupts_ap() {
    if(fred_enabled) {
        setup_fred_ap();
    } else {
        setup_idt_ap();
    }
}

void x86_64_set_rsp0_stack(virt_addr_t stack) {
    if(fred_enabled) {
        // @note: we FORCE align down here since on first ctx switch the stack will not be aligned
        // this SHOULD be fine
        __wrmsr(IA32_FRED_RSP0, ALIGN_DOWN(stack, 64));
    } else {
        tss_t* tss = CPU_LOCAL_READ(cpu_tss);
        tss->rsp0 = stack;
    }
}

bool x86_64_fred_enabled() {
    return fred_enabled;
}
