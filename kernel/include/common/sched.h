#pragma once
#include "memory/memory.h"

#include <arch/thread.h>
#include <memory/vmm.h>

// Per-CPU run queue.  Non-idle runnable threads are kept in a FIFO singly-linked
// list (run_queue_head → … → run_queue_tail).  The idle thread is stored
// separately and is never placed inside the queue; it is returned by
// find_next_thread only when the queue contains no runnable thread.
typedef struct {
    thread_t* idle_thread;
    thread_t* run_queue_head; // front of the run queue (next to be scheduled)
    thread_t* run_queue_tail; // back of the run queue (last enqueued)
} scheduler_t;

void sched_init_bsp();
void sched_init_ap();

void sched_start();

void sched_yield();
void sched_yield_status(thread_status_t new_status);

void sched_wake_thread_id(uint32_t tid);
thread_t* sched_get_thread(uint32_t tid);
thread_t* sched_thread_kernel_init(virt_addr_t entry_point);
thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point, virt_addr_t stack);
void sched_start_thread(thread_t* thread);
void sched_wake_thread(thread_t* to_wake);

void sched_add_thread(thread_t* thread);
void sched_remove_thread(thread_t* thread);
thread_t* sched_get_current_thread();

void sched_preempt_enable();
void sched_preempt_disable();
