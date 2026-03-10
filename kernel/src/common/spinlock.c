#include <common/arch.h>
#include <common/dw.h>
#include <common/interrupts.h>
#include <common/sched.h>
#include <stdint.h>

static inline bool spinlock_try_lock(volatile uint32_t* lock) {
    return !__atomic_test_and_set(lock, __ATOMIC_ACQUIRE);
}

static inline void spinlock_unlock_raw(volatile uint32_t* lock) {
    __atomic_clear(lock, __ATOMIC_RELEASE);
}

void spinlock_lock_raw(volatile uint32_t* lock) {
    while(true) {
        if(spinlock_try_lock(lock)) return;

        while(__atomic_load_n(lock, __ATOMIC_RELAXED)) {
            arch_pause();
        }
    }
}
void spinlock_lock(spinlock_t* lock) {
    sched_preempt_disable();
    // ASSERT(!ARCH_CPU_CURRENT_READ(flags.in_interrupt_soft) && !ARCH_CPU_CURRENT_READ(flags.in_interrupt_hard));
    spinlock_lock_raw(&lock->__lock);
}

void spinlock_unlock(spinlock_t* lock) {
    spinlock_unlock_raw(&lock->__lock);
    // ASSERT(!ARCH_CPU_CURRENT_READ(flags.in_interrupt_soft) && !ARCH_CPU_CURRENT_READ(flags.in_interrupt_hard));
    sched_preempt_enable();
}

void spinlock_lock_nodw(nodw_spinlock_t* lock) {
    sched_preempt_disable();
    dw_disable();
    // ASSERT(!ARCH_CPU_CURRENT_READ(flags.in_interrupt_hard));
    spinlock_lock_raw(&lock->__lock);
}

void spinlock_unlock_nodw(nodw_spinlock_t* lock) {
    spinlock_unlock_raw(&lock->__lock);
    // ASSERT(!ARCH_CPU_CURRENT_READ(flags.in_interrupt_hard));
    dw_enable();
    sched_preempt_enable();
}

uint64_t spinlock_lock_noint(noint_spinlock_t* lock) {
    uint64_t previous_state = interrupts_enabled();
    disable_interrupts();
    sched_preempt_disable();
    dw_disable();
    spinlock_lock_raw(&lock->__lock);
    return previous_state;
}

void spinlock_unlock_noint(noint_spinlock_t* lock, uint64_t interrupt_state) {
    spinlock_unlock_raw(&lock->__lock);
    dw_enable();
    sched_preempt_enable();
    if(interrupt_state) {
        enable_interrupts();
    }
}
