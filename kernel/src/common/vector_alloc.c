#include <assert.h>
#include <common/spinlock.h>
#include <common/vector_alloc.h>
#include <stdbool.h>
#include <stdint.h>

static uint8_t g_vector_bitmap[256] = { 0 };
static spinlock_t g_vector_lock = 0;

#define VECTOR_START 0x30
#define VECTOR_END 0xEF

int alloc_interrupt_vector(void) {
    uint64_t flags = spinlock_critical_lock(&g_vector_lock);
    for(int v = VECTOR_START; v <= VECTOR_END; ++v) {
        if(!g_vector_bitmap[v]) {
            g_vector_bitmap[v] = 1;
            spinlock_critical_unlock(&g_vector_lock, flags);
            return v;
        }
    }
    spinlock_critical_unlock(&g_vector_lock, flags);
    return -1;
}

int alloc_specific_interrupt_vector(int vector) {
    assert(vector >= 0 && vector < 256);
    if(vector < VECTOR_START || vector > VECTOR_END) {
        return -1;
    }
    uint64_t flags = spinlock_critical_lock(&g_vector_lock);
    if(g_vector_bitmap[vector]) {
        spinlock_critical_unlock(&g_vector_lock, flags);
        return -1;
    }
    g_vector_bitmap[vector] = 1;
    spinlock_critical_unlock(&g_vector_lock, flags);
    return 0;
}

void free_interrupt_vector(int vector) {
    assert(vector >= 0 && vector < 256);
    uint64_t flags = spinlock_critical_lock(&g_vector_lock);
    g_vector_bitmap[vector] = 0;
    spinlock_critical_unlock(&g_vector_lock, flags);
}
