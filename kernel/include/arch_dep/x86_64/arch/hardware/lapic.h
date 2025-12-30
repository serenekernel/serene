#pragma once
#include <stdint.h>
#include <common/memory.h>

void lapic_init_bsp();
void lapic_init_ap();

uint32_t lapic_get_id();
bool lapic_is_bsp();

void lapic_eoi();

void lapic_timer_oneshot_us(uint32_t microseconds);
void lapic_timer_oneshot_ms(uint32_t milliseconds);
void lapic_timer_stop();

void ioapic_init(uint32_t id, phys_addr_t phys_addr);