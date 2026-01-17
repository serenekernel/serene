#include <assert.h>
#include <memory/memory.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/thread.h>
#include <common/spinlock.h>
#include <memory/vmm.h>

// @todo: Implement proper scheduler for aarch64
// For now, all scheduler functions are stubbed

typedef struct {
    thread_t* idle_thread;
    thread_t* reaper_thread;
    thread_t* thread_head;
} scheduler_t;

spinlock_t g_sched_lock = 0;
scheduler_t g_scheduler = {0};

thread_t* sched_thread_kernel_init(virt_addr_t entry_point) {
    (void) entry_point;
    // @todo: 
    assert(false && "unimplemented");
    return nullptr;
}

thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point) {
    (void) address_space;
    (void) entry_point;
    // @todo: 
    assert(false && "unimplemented");
    return nullptr;
}

void sched_add_thread(thread_t* thread) {
    (void) thread;
    // @todo: 
    assert(false && "unimplemented");
}

void sched_remove_thread(thread_t* thread) {
    (void) thread;
    // @todo: 
    assert(false && "unimplemented");
}

void sched_yield(void) {
    // @todo: 
    assert(false && "unimplemented");
}

void sched_init_bsp(void) {
    // @todo: 
    assert(false && "unimplemented");
}

void sched_init_ap(void) {
    // @todo: 
    assert(false && "unimplemented");
}

void sched_start_bsp(void) {
    // @todo: 
    assert(false && "unimplemented");
}

thread_t* sched_get_thread(uint32_t tid) {
    (void) tid;
    // @todo: 
    assert(false && "unimplemented");
    return nullptr;
}