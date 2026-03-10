#include "common/interrupts.h"
#include "common/sched.h"
#include "memory/memory.h"
#include "memory/vmm.h"

#include <arch/cpu_local.h>
#include <assert.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/dw.h>

static bool __dw_enable() {
    arch_memory_barrier();
    size_t status = CPU_LOCAL_READ(dw_data.dw_counter);
    assert(status > 0 && "DW counter underflow in __dw_enable");
    CPU_LOCAL_DEC(dw_data.dw_counter);
    return status == 1;
}

void cleanup_created_dw(dw_item_t* item) {
    vmm_free(&kernel_allocator, (virt_addr_t) item);
}

dw_item_t* dw_create(dw_func_t func, void* data) {
    dw_item_t* item = (dw_item_t*) vmm_alloc_object(&kernel_allocator, sizeof(dw_item_t));
    item->func = func;
    item->data = data;
    item->cleanup_func = cleanup_created_dw;
    return item;
}

void dw_queue(dw_item_t* item) {
    sched_preempt_disable();
    dw_disable();
    item->next = CPU_LOCAL_READ(dw_data.defered_work_head);
    CPU_LOCAL_WRITE(dw_data.defered_work_head, item);
    dw_enable();
    sched_preempt_enable();
}


void dw_process() {
    dw_disable();
    while(true) {
        sched_preempt_disable();
        if(CPU_LOCAL_READ(dw_data.defered_work_head) == nullptr) {
            sched_preempt_enable();
            __dw_enable();
            return;
        }

        uint64_t __irq = interrupts_enabled();
        disable_interrupts();
        dw_item_t* dw_item = CPU_LOCAL_READ(dw_data.defered_work_head);
        CPU_LOCAL_WRITE(dw_data.defered_work_head, dw_item->next);
        if(__irq) {
            enable_interrupts();
        }
        sched_preempt_enable();

        dw_item->func(dw_item->data);

        if(dw_item->cleanup_func != nullptr) dw_item->cleanup_func(dw_item);
    }
}

void dw_disable() {
    assert(CPU_LOCAL_READ(dw_data.dw_counter) < UINT32_MAX && "DW counter overflow in dw_disable");
    CPU_LOCAL_INC(dw_data.dw_counter);
    arch_memory_barrier();
}

void dw_enable() {
    if(__dw_enable()) dw_process();
}
