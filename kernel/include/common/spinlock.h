#include <common/arch.h>
#include <stdint.h>

typedef volatile uint32_t spinlock_t;

static inline void spinlock_lock(spinlock_t* lock) {
    while(__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) {
        arch_pause();
    }
}

[[nodiscard]] static inline int spinlock_try_lock(spinlock_t* lock) {
    return !__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE);
}

static inline void spinlock_unlock(spinlock_t* lock) {
    __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

[[nodiscard]] static inline uint64_t spinlock_critical_lock(spinlock_t* lock) {
    uint64_t flags = arch_get_flags();
    spinlock_lock(lock);
    return flags;
}

static inline void spinlock_critical_unlock(spinlock_t* lock, uint64_t flags) {
    spinlock_unlock(lock);
    arch_set_flags(flags);
}
