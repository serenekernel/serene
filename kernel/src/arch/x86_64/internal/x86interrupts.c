#include "arch/interrupts.h"
#include "common/sched.h"

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

void x86_64_handle_page_fault(interrupt_frame_t* frame) {
    vm_fault_reason_t reason = VM_FAULT_UKKNOWN;
    if((frame->error & (1 << 0)) == 0) {
        reason = VM_FAULT_NOT_PRESENT;
    }
    if(vm_handle_page_fault(reason, frame->interrupt_data)) {
        return;
    }

    arch_panic_int(frame);
}

void x86_64_handle_ipi(interrupt_frame_t* frame) {
    (void) frame;
    ipi_handle();
}

void setup_interrupts_bsp() {
    fred_enabled = __cpuid_is_feature_supported(CPUID_FEATURE_FRED);
    printf("fred support: %d\n", fred_enabled);

    if(fred_enabled) {
        setup_fred_bsp();
    } else {
        setup_idt_bsp();
    }

    ipi_allocate_vector();

    for(int i = 0; i < 0x20; i++) {
        if(i == 0x03 || i == 0x0E) {
            continue;
        }
        register_interrupt_handler(i, arch_panic_int);
    }

    register_interrupt_handler(0x0E, x86_64_handle_page_fault);
    register_interrupt_handler(ipi_get_vector(), x86_64_handle_ipi);
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

    bool root_handler = !CPU_LOCAL_READ(current_thread)->thread_common.in_interrupt_handler;
    if(root_handler) {
        CPU_LOCAL_READ(current_thread)->thread_common.in_interrupt_handler = true;
    }

    sched_preempt_disable();
    dw_disable();

    fn_interrupt_handler handler = interrupt_handlers[frame->vector];
    if(handler) {
        handler(frame);
    }

    if(frame->vector >= 0x20) {
        lapic_eoi();
    }

    enable_interrupts();
    dw_enable();
    disable_interrupts();

    sched_preempt_enable();
    if(root_handler) {
        CPU_LOCAL_READ(current_thread)->thread_common.in_interrupt_handler = false;
    }
}
