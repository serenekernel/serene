#include "memory/memory.h"
#include <memory/vmm.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/spinlock.h>

uint32_t next_pid = 1;
process_t* g_proc_head = nullptr;

extern spinlock_t g_sched_lock;

process_t* process_create() {
    process_t* process = (process_t*) vmm_alloc_backed(&kernel_allocator, ALIGN_UP(sizeof(process_t), PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    process->address_space = (vm_allocator_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    vmm_user_init(process->address_space, 0x40000000, 0x80000000);
    process->pid = next_pid++;

    uint64_t __spinflags = spinlock_critical_lock(&g_sched_lock);
    process->prev = (struct process*)nullptr;
    process->next = (struct process*)g_proc_head;
    if(g_proc_head != nullptr) {
        g_proc_head->prev = (struct process*)process;
    }
    g_proc_head = process;
    spinlock_critical_unlock(&g_sched_lock, __spinflags);

    return process;
}

void process_destroy(process_t* process) {
    uint64_t __spinflags = spinlock_critical_lock(&g_sched_lock);

    thread_t* current = (thread_t*) process->proc_thread_head;
    while(current != nullptr) {
        current->thread_common.happy_to_die = true;
        current = (thread_t*) current->proc_next;
    }
    // thread count will be lowered by the reaper as threads die
    // once it hits 0 the process will be freed
    process->happy_to_die = true;
    spinlock_critical_unlock(&g_sched_lock, __spinflags);
}

void process_add_thread(process_t* process, thread_t* thread) {
    uint64_t __spinflags = spinlock_critical_lock(&g_sched_lock);

    thread->thread_common.process = (struct process*) process;
    thread->proc_next = nullptr;

    if(process->proc_thread_head == nullptr) {
        process->proc_thread_head = thread;
    } else {
        thread_t* current = (thread_t*) process->proc_thread_head;
        while(current->proc_next != nullptr) {
            current = (thread_t*) current->proc_next;
        }
        current->proc_next = (struct thread*)thread;
    }

    process->thread_count++;
    spinlock_critical_unlock(&g_sched_lock, __spinflags);
}

void process_remove_thread(process_t* process, thread_t* thread) {
    uint64_t __spinflags = spinlock_critical_lock(&g_sched_lock);

    if(process->proc_thread_head == thread) {
        process->proc_thread_head = (thread_t*) thread->proc_next;
    } else {
        thread_t* current = (thread_t*) process->proc_thread_head;
        while(current != nullptr && current->proc_next != (struct thread*) thread) {
            current = (thread_t*) current->proc_next;
        }
        if(current != nullptr) {
            current->proc_next = thread->proc_next;
        }
    }

    thread->thread_common.happy_to_die = true;
    process->thread_count--;
    spinlock_critical_unlock(&g_sched_lock, __spinflags);
}
