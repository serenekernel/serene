#pragma once
#include "memory/vmm.h"

#include <stdint.h>

typedef enum {
    THREAD_STATUS_RUNNING,
    THREAD_STATUS_READY,
    THREAD_STATUS_BLOCKED,
    THREAD_STATUS_TERMINATED
} thread_status_t;

typedef struct thread {
    void* process;
    uint32_t tid;
    vm_allocator_t* address_space;
    thread_status_t status;
    struct thread* sched_next;
    struct thread* proc_next;
} thread_common_t;

#include <arch/sched.h>

void sched_init_bsp();
void sched_init_ap();
void sched_yield();

thread_t* sched_thread_kernel_init(virt_addr_t entry_point);
thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point);

void sched_add_thread(thread_t* thread);
void sched_remove_thread(thread_t* thread);
thread_t* sched_get_current_thread();
