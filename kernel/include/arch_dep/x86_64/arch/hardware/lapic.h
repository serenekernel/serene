#pragma once
#include <common/memory.h>
#include <stdint.h>

typedef struct {
    uint32_t id;
    volatile virt_addr_t mmio;
    uint32_t max_redirection_entry;
} io_apic_t;

typedef struct {
    uint8_t bus;
    uint8_t source;
    uint32_t gsi;
    uint16_t flags;
} io_apic_iso_t;

void lapic_init_bsp();
void lapic_init_ap();

uint32_t lapic_get_id();
bool lapic_is_bsp();

void lapic_eoi();

void lapic_timer_oneshot_us(uint32_t microseconds);
void lapic_timer_oneshot_ms(uint32_t milliseconds);
void lapic_timer_stop();

void ioapic_init(uint32_t id, phys_addr_t phys_addr);
void ioapic_add_iso(uint8_t bus, uint8_t source, uint32_t gsi, uint16_t flags);
void ioapic_setup();

void ioapic_mask_irq(uint8_t irq);
void ioapic_unmask_irq(uint8_t irq);
