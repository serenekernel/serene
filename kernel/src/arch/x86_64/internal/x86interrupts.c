#include "arch/interrupts.h"

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
    fred_enabled = __cpuid_is_feature_supported(CPUID_FEATURE_FRED);
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

void x86_64_dispatch_interrupt(interrupt_frame_t* frame) {
    arch_restore_uap(true);

    if(frame->vector != 0x20 && frame->vector != 0xf0) {
        printf("Interrupt received: 0x%02X on lapic %u\n", frame->vector, lapic_get_id());
    }

    if(frame->vector < 0x20 && frame->vector != 0x03) {
        if(frame->vector == 0x0E) {
            vm_fault_reason_t reason = VM_FAULT_UKKNOWN;
            if((frame->error & (1 << 0)) == 0) {
                reason = VM_FAULT_NOT_PRESENT;
            }
            if(vm_handle_page_fault(reason, frame->interrupt_data)) {
                return;
            }
        }
        arch_panic_int(frame);
    }

    if(frame->vector == 0xf0) {
        ipi_handle();
        lapic_eoi();
        return;
    }

    if(interrupt_handlers[frame->vector]) {
        void (*handler)(interrupt_frame_t*) = (void (*)(interrupt_frame_t*)) interrupt_handlers[frame->vector];
        handler(frame);
    } else {
        printf("Unhandled interrupt: 0x%02X\n", frame->vector);
    }

    // @note: we don't send an for 0x20 as the scheduler handles that
    if(frame->vector != 0x20) {
        lapic_eoi();
    }
}
