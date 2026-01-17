#include <arch/thread.h>
#include <memory/memory.h>

#include <assert.h>

void sched_arch_init_bsp() {
    assert(false && "unimplemented");
}

void sched_arch_init_thread(thread_t* thread, virt_addr_t entry_point) {
    (void)thread;
    (void)entry_point;
    assert(false && "unimplemented");
}

void sched_arch_yield_prepare(thread_t* current_thread, thread_t* next_thread) {
    (void)current_thread;
    (void)next_thread;
    assert(false && "unimplemented");
}