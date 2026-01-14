#pragma once
#include <memory/vmm.h>
#include <arch/thread.h>

void sched_init_bsp();
void sched_start_bsp();

void sched_init_ap();

void sched_yield();
void sched_yield_status(thread_status_t new_status);

void sched_wake_thread_id(uint32_t tid);
thread_t* sched_get_thread(uint32_t tid);
thread_t* sched_thread_kernel_init(virt_addr_t entry_point);
thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point);

void sched_add_thread(thread_t* thread);
void sched_remove_thread(thread_t* thread);
thread_t* sched_get_current_thread();
