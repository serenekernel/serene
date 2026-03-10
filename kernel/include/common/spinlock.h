#pragma once
#include <common/arch.h>
#include <common/dw.h>
#include <common/interrupts.h>
#include <stdint.h>

#define SPINLOCK_INIT { 0 }

typedef volatile struct {
    volatile uint32_t __lock;
} spinlock_t;

typedef volatile struct {
    volatile uint32_t __lock;
} nodw_spinlock_t;

typedef volatile struct {
    volatile uint32_t __lock;
} noint_spinlock_t;

void spinlock_lock(spinlock_t* lock);
void spinlock_unlock(spinlock_t* lock);
void spinlock_lock_nodw(nodw_spinlock_t* lock);
void spinlock_unlock_nodw(nodw_spinlock_t* lock);
uint64_t spinlock_lock_noint(noint_spinlock_t* lock);
void spinlock_unlock_noint(noint_spinlock_t* lock, uint64_t interrupt_state);
