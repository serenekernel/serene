#include <arch/hardware/lapic.h>
#include <arch/internal/cpuid.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/io.h>
#include <memory/memory.h>
#include <memory/vmm.h>
#include <stdint.h>
#include <stdio.h>

// lapic registers
#define LAPIC_ID 0x20
#define LAPIC_VERSION 0x30
#define LAPIC_TPR 0x80
#define LAPIC_APR 0x90
#define LAPIC_PPR 0xA0
#define LAPIC_EOI 0xB0
#define LAPIC_RRD 0xC0
#define LAPIC_LDR 0xD0
#define LAPIC_DFR 0xE0
#define LAPIC_SPURIOUS 0xF0
#define LAPIC_ISR 0x100
#define LAPIC_TMR 0x180
#define LAPIC_IRR 0x200
#define LAPIC_ERROR_STATUS 0x280

#define LAPIC_ICR_LOW 0x300
#define LAPIC_ICR_HIGH 0x310
#define LAPIC_X2APIC_ICR 0x300

#define LAPIC_LVT_TIMER 0x320
#define LAPIC_LVT_THERMAL 0x330
#define LAPIC_LVT_PERF 0x340
#define LAPIC_LVT_LINT0 0x350
#define LAPIC_LVT_LINT1 0x360
#define LAPIC_LVT_ERROR 0x370

// Delivery Mode
#define LAPIC_DELMODE_FIXED 0x000
#define LAPIC_DELMODE_LOWEST 0x100
#define LAPIC_DELMODE_SMI 0x200
#define LAPIC_DELMODE_NMI 0x400
#define LAPIC_DELMODE_INIT 0x500
#define LAPIC_DELMODE_STARTUP 0x600
#define LAPIC_DELMODE_EXTINT 0x700

// Destination Mode
#define LAPIC_DESTMODE_PHYSICAL 0x000
#define LAPIC_DESTMODE_LOGICAL 0x800

// Delivery Status
#define LAPIC_STATUS_IDLE 0x000
#define LAPIC_STATUS_PENDING 0x1000

// Level
#define LAPIC_LEVEL_DEASSERT 0x0000
#define LAPIC_LEVEL_ASSERT 0x4000

// Trigger Mode
#define LAPIC_TRIGGER_EDGE 0x0000
#define LAPIC_TRIGGER_LEVEL 0x8000

// Mask
#define LAPIC_MASK_UNMASKED 0x0000
#define LAPIC_MASK_MASKED 0x10000

// Shorthand
#define LAPIC_SHORTHAND_NONE 0x00000
#define LAPIC_SHORTHAND_SELF 0x40000
#define LAPIC_SHORTHAND_ALL_INCL_SELF 0x80000
#define LAPIC_SHORTHAND_ALL_EXCL_SELF 0xC0000

static bool x2apic_mode = false;
static virt_addr_t apic_base_address = 0;

bool __x2apic_supported(void) {
    return __cpuid_is_feature_supported(CPUID_FEATURE_X2APIC);
}

static void apic_enable_mode_bsp() {
    uint64_t msr = __rdmsr(IA32_APIC_BASE_MSR);
    msr |= APIC_BASE_ENABLE;
    __wrmsr(IA32_APIC_BASE_MSR, msr);
    x2apic_mode = __x2apic_supported();

    if(x2apic_mode) {
        printf("enabling in x2apic mode\n");
        return;
    }

    printf("x2apic mode not supported, using xapic mode\n");

    uint8_t cpuid_result = (uint8_t) (__cpuid(0x80000008, 0, CPUID_EAX) & 0xff);
    printf("max phys bits: %u\n", cpuid_result);
    assert(cpuid_result > 36 && "physical address bits > 36");
    assert(cpuid_result + 12 < 64 && "physical address bits + 12 < 64");

    apic_base_address = (virt_addr_t) vmm_alloc(&kernel_allocator, 1);
    vm_map_page(&kernel_allocator, apic_base_address, (msr & 0xFFFFF000), VM_ACCESS_KERNEL, VM_CACHE_WRITE_THROUGH, VM_READ_WRITE);

    printf("apic base address: 0x%lx\n", apic_base_address);
}

static void apic_enable_mode_ap(void) {
    uint64_t msr = __rdmsr(IA32_APIC_BASE_MSR);
    msr |= APIC_BASE_ENABLE;
    __wrmsr(IA32_APIC_BASE_MSR, msr);
}


uint32_t lapic_read(uint32_t reg) {
    if(x2apic_mode) {
        return (uint32_t) __rdmsr(IA32_X2APIC_BASE_MSR + (reg >> 4));
    } else {
        return mmio_read_u32(apic_base_address + reg);
    }
}

void lapic_write(uint32_t reg, uint32_t value) {
    if(x2apic_mode) {
        __wrmsr(IA32_X2APIC_BASE_MSR + (reg >> 4), value);
    } else {
        mmio_write_u32(apic_base_address + reg, value);
    }
}

uint64_t lapic_read64(uint32_t reg) {
    if(x2apic_mode) {
        return (uint32_t) __rdmsr(IA32_X2APIC_BASE_MSR + (reg >> 4));
    } else {
        // @todo: im sure this doesn't work for ALL registers
        uint64_t val = 0;
        val |= (uint64_t) mmio_read_u32(apic_base_address + reg);
        val |= (uint64_t) mmio_read_u32(apic_base_address + (reg + 0x10)) << 32;
        return val;
    }
}

void lapic_write64(uint32_t reg, uint64_t value) {
    if(x2apic_mode) {
        __wrmsr(IA32_X2APIC_BASE_MSR + (reg >> 4), value);
    } else {
        // @todo: im sure this doesn't work for ALL registers
        mmio_write_u32(apic_base_address + reg, (value & 0xFFFFFFFF));
        mmio_write_u32(apic_base_address + (reg + 0x10), (value >> 32));
    }
}


uint32_t lapic_get_id() {
    if(x2apic_mode) {
        return lapic_read(LAPIC_ID);
    } else {
        return (lapic_read(LAPIC_ID) >> 24) & 0xFF;
    }
}

bool lapic_is_bsp() {
    uint64_t msr = __rdmsr(IA32_APIC_BASE_MSR);
    return (msr & APIC_BASE_BSP) != 0;
}


void lapic_eoi() {
    lapic_write(LAPIC_EOI, 0);
}

void lapic_configure() {
    lapic_write(LAPIC_TPR, 0);
    if(!x2apic_mode) {
        lapic_write(LAPIC_DFR, 0xF0000000);
        lapic_write(LAPIC_LDR, 0x01000000);
    }

    lapic_write(LAPIC_LVT_TIMER, LAPIC_MASK_MASKED);
    lapic_write(LAPIC_LVT_THERMAL, LAPIC_MASK_MASKED);
    lapic_write(LAPIC_LVT_PERF, LAPIC_MASK_MASKED);
    lapic_write(LAPIC_LVT_LINT0, LAPIC_MASK_MASKED);
    lapic_write(LAPIC_LVT_LINT1, LAPIC_MASK_MASKED);
    lapic_write(LAPIC_LVT_ERROR, LAPIC_MASK_MASKED);

    uint32_t spurious = lapic_read(LAPIC_SPURIOUS);
    spurious |= (1 << 8); // bit 8: apic enable bit
    spurious |= 0xFF; // vector: 0xFF
    lapic_write(LAPIC_SPURIOUS, spurious);
}

void lapic_timer_init_bsp();
void lapic_timer_init_ap();

void lapic_init_bsp() {
    apic_enable_mode_bsp();

    lapic_configure();
    lapic_timer_init_bsp();
    ioapic_setup();
    printf("initialized in %s mode for lapic %d (bsp)\n", x2apic_mode ? "x2APIC" : "xAPIC", lapic_get_id());
}

void lapic_init_ap() {
    disable_interrupts();
    apic_enable_mode_ap();

    lapic_configure();
    lapic_timer_init_ap();
    printf("initialized in %s mode for lapic %d\n", x2apic_mode ? "x2APIC" : "xAPIC", lapic_get_id());
}

void lapic_send_raw_ipi(uint32_t apic_id) {
    uint64_t icr = 0;

    if(x2apic_mode) {
        // for x2apic, the destination field is bits 63-32
        icr |= (((uint64_t) apic_id) << 32);
    } else {
        // for xapic, the destination field is bits 63-56
        icr |= (((uint64_t) apic_id) << 56);
    }

    icr |= LAPIC_SHORTHAND_NONE;
    icr |= LAPIC_TRIGGER_EDGE;
    icr |= LAPIC_LEVEL_DEASSERT;
    icr |= LAPIC_DESTMODE_PHYSICAL;
    icr |= LAPIC_DELMODE_FIXED;
    icr |= 0xf0; // vector


    if(x2apic_mode) {
        lapic_write64(LAPIC_X2APIC_ICR, icr);
    } else {
        lapic_write64(LAPIC_ICR_LOW, icr);

        while(lapic_read(LAPIC_ICR_LOW) & (1 << 12)) {
            __builtin_ia32_pause();
        }
    }
}

void lapic_broadcast_raw_ipi() {
    uint64_t icr = 0;

    icr |= LAPIC_SHORTHAND_ALL_EXCL_SELF;
    icr |= LAPIC_TRIGGER_EDGE;
    icr |= LAPIC_LEVEL_DEASSERT;
    icr |= LAPIC_DESTMODE_PHYSICAL;
    icr |= LAPIC_DELMODE_FIXED;
    icr |= 0xf0; // vector

    if(x2apic_mode) {
        lapic_write64(LAPIC_X2APIC_ICR, icr);
    } else {
        lapic_write64(LAPIC_ICR_LOW, icr);

        while(lapic_read(LAPIC_ICR_LOW) & (1 << 12)) {
            __builtin_ia32_pause();
        }
    }
}
