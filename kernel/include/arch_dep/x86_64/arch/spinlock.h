#include <common/arch.h>
#include <stdint.h>

typedef volatile uint32_t spinlock_t;

static inline void spinlock_lock(spinlock_t* lock) {
    while(__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) { arch_pause(); }
}

[[nodiscard]] static inline int spinlock_try_lock(spinlock_t* lock) {
    return !__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE);
}

static inline void spinlock_unlock(spinlock_t* lock) {
    __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

[[nodiscard]] static inline uint64_t local_irq_save(void) {
    uint64_t flags;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(flags)::"memory");
    return flags;
}

static inline void local_irq_restore(uint64_t flags) {
    __asm__ volatile("push %0; popfq" ::"r"(flags) : "memory");
}

[[nodiscard]] static inline uint64_t spinlock_uninterruptable_lock(spinlock_t* lock) {
    uint64_t flags = local_irq_save();
    spinlock_lock(lock);
    return flags;
}

static inline void spinlock_uninterruptable_unlock(spinlock_t* lock, uint64_t flags) {
    spinlock_unlock(lock);
    local_irq_restore(flags);
}
