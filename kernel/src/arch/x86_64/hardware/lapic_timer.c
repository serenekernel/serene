#include "arch/cpuid.h"
#include "memory/memory.h"
#include "memory/vmm.h"

#include <arch/hardware/lapic.h>
#include <arch/hardware/pit.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/io.h>
#include <stdint.h>
#include <stdio.h>

#define LAPIC_TIMER_INIT_COUNT 0x380
#define LAPIC_TIMER_CUR_COUNT 0x390
#define LAPIC_TIMER_DIV 0x3E0
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_MASK_MASKED 0x10000

// defined in lapic.c but are private so we must pry them out
uint32_t lapic_read(uint32_t reg);
void lapic_write(uint32_t reg, uint32_t value);

uint32_t ticks_per_us = 0;

void lapic_timer_init_bsp() {
    lapic_write(LAPIC_TIMER_DIV, 0x3);
    lapic_write(LAPIC_TIMER_INIT_COUNT, 0xFFFFFFFF);

    pit_sleep_us(10000); // 10 ms

    uint32_t elapsed = 0xFFFFFFFF - lapic_read(LAPIC_TIMER_CUR_COUNT);
    ticks_per_us = elapsed / 10000ULL;

    printf("apic timer calibrated: %d ticks/us\n", ticks_per_us);
}

void lapic_timer_init_ap() {
    lapic_write(LAPIC_TIMER_DIV, 0x3);
}

void lapic_timer_oneshot_us(uint32_t microseconds) {
    lapic_write(LAPIC_TIMER_DIV, 0x3);
    lapic_write(LAPIC_LVT_TIMER, 0x20);
    uint32_t ticks = (uint32_t) (microseconds * ticks_per_us);
    lapic_write(LAPIC_TIMER_INIT_COUNT, ticks);
}

void lapic_timer_oneshot_ms(uint32_t milliseconds) {
    lapic_timer_oneshot_us(milliseconds * 1000);
}

void lapic_timer_stop() {
    lapic_write(LAPIC_LVT_TIMER, LAPIC_MASK_MASKED);
}
