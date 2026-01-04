#pragma once
#include <common/memory.h>
#include <stdint.h>

typedef struct {
    uint32_t id;
    volatile virt_addr_t mmio;
    uint32_t max_redirection_entry;
} io_apic_t;

void lapic_init_bsp();
void lapic_init_ap();

uint32_t lapic_get_id();
bool lapic_is_bsp();

void lapic_eoi();

void lapic_timer_oneshot_us(uint32_t microseconds);
void lapic_timer_oneshot_ms(uint32_t milliseconds);
void lapic_timer_stop();

void ioapic_init(uint32_t id, phys_addr_t phys_addr);
void ioapic_setup();
void ioapic_map_irq(io_apic_t* ioapic, uint8_t irq, uint8_t vector, uint8_t destination);
