#include <arch/internal/gdt.h>
#include <arch/hardware/lapic.h>
#include <common/arch.h>
#include <common/interrupts.h>
#include <common/ipi.h>
#include <memory/memory.h>
#include <memory/vmm.h>
#include <stdint.h>

typedef struct {
    uint16_t base_low;

    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;

    uint16_t base_mid;
    uint32_t base_high;
    uint32_t zero;
} __attribute__((packed)) idt_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idtr_t;

extern void __load_idt(idtr_t* idtr);
static idt_entry_t idt[256];
extern void* x86_isr_stub_table[256];

void set_idtr_entry(int vector, void (*isr)(), uint8_t type_attr, int ist) {
    virt_addr_t isr_addr = (virt_addr_t) isr;
    idt[vector] = (idt_entry_t) { .base_low = isr_addr & 0xFFFF, .base_mid = (isr_addr >> 16) & 0xFFFF, .selector = 0x08, .ist = ist, .type_attr = type_attr, .base_high = (isr_addr >> 32) & 0xFFFFFFFF };
}

void setup_interrupts_bsp() {
    idtr_t idtr;
    idtr.limit = (sizeof(idt_entry_t) * 256) - 1;
    idtr.base = (virt_addr_t) &idt;

    for(int i = 0; i < 256; ++i) {
        void (*handler)() = x86_isr_stub_table[i];
        set_idtr_entry(i, handler, 0x8E, 0);
    }

    // #BP
    set_idtr_entry(0x03, x86_isr_stub_table[0x03], 0xEE, 0);

    // #NMI
    set_idtr_entry(0x02, x86_isr_stub_table[0x02], 0x8E, 1);
    // #DF
    set_idtr_entry(0x08, x86_isr_stub_table[0x08], 0x8E, 2);
    // #MC
    set_idtr_entry(0x12, x86_isr_stub_table[0x12], 0x8E, 3);

    __load_idt(&idtr);
}

void setup_interrupts_ap() {
    idtr_t idtr;
    idtr.limit = (sizeof(idt_entry_t) * 256) - 1;
    idtr.base = (virt_addr_t) &idt;

    __load_idt(&idtr);
}


void x86_64_dispatch_interupt(interrupt_frame_t* frame) {
    (void) frame;
    if(frame->vector != 0x20) {
        printf("Interrupt received: 0x%02X on lapic %u\n", frame->vector, lapic_get_id());
    }

    if(frame->vector < 0x20 && frame->vector != 0x03) {
        if(frame->vector == 0x0E) {
            vm_fault_reason_t reason = VM_FAULT_UKKNOWN;
            if((frame->error & (1 << 0)) == 0) {
                reason = VM_FAULT_NOT_PRESENT;
            }
            if(vm_handle_page_fault(reason, __read_cr2())) {
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