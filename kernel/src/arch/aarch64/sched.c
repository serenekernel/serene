#include <assert.h>
#include <memory/memory.h>
#include <common/process.h>
#include <memory/vmm.h>

thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point) {
    (void) address_space;
    (void) entry_point;
    // @todo: stub...
    assert(false);
    return nullptr;
}

void sched_add_thread(thread_t* thread) {
    (void) thread;
    // @todo: stub...
    assert(false);
}