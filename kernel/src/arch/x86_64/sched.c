#include "arch/msr.h"
#include "common/memory.h"

#include <assert.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <memory/vmm.h>
#include <stdint.h>

typedef struct {
    spinlock_t sched_lock;
    thread_t* idle_thread;
    thread_t* thread_head;
} scheduler_t;

typedef struct {
    thread_t* current_thread;
} kernel_cpu_local_t;

scheduler_t g_scheduler;

void idle_thread() {
    while(1) {
        sched_yield();
    }
}

void sched_init_bsp() {
    g_scheduler.sched_lock = 0;
    thread_t* thread = sched_thread_init(&kernel_allocator, (virt_addr_t) idle_thread);
    thread->thread_common.tid = 0;
    g_scheduler.idle_thread = thread;
    g_scheduler.thread_head = thread;

    kernel_cpu_local_t* kernel_cpu_local = (kernel_cpu_local_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    kernel_cpu_local->current_thread = g_scheduler.idle_thread;
    __wrmsr(IA32_GS_BASE_MSR, (uint64_t) kernel_cpu_local);
}

void sched_init_ap() {
    kernel_cpu_local_t* kernel_cpu_local = (kernel_cpu_local_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    kernel_cpu_local->current_thread = g_scheduler.idle_thread;
    __wrmsr(IA32_GS_BASE_MSR, (uint64_t) kernel_cpu_local);
}

thread_t* sched_thread_init(vm_allocator_t* address_space, virt_addr_t entry_point) {
    thread_t* thread = (thread_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    thread->thread_common.process = nullptr;
    thread->thread_common.tid = 0;
    thread->thread_common.address_space = address_space;
    thread->thread_common.sched_next = nullptr;
    thread->thread_common.proc_next = nullptr;
    thread->thread_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->syscall_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->kernel_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->thread_common.status = THREAD_STATUS_READY;

    // @todo: holy shit what the FUCK AM I THINKING
    // Set up initial stack frame for context switch
    // We need to push the SysV ABI callee-saved registers: rbx, rbp, r12, r13, r14, r15
    // and the return address (entry point)
    uint64_t* stack = (uint64_t*) thread->syscall_rsp;
    *(--stack) = entry_point; // Return address (where ret will jump to)
    *(--stack) = 0; // r15
    *(--stack) = 0; // r14
    *(--stack) = 0; // r13
    *(--stack) = 0; // r12
    *(--stack) = 0; // rbp
    *(--stack) = 0; // rbx
    thread->syscall_rsp = (virt_addr_t) stack;

    return thread;
}

void __context_switch(thread_t* old_thread, thread_t* new_thread);
void __userspace_init(virt_addr_t user_rip, virt_addr_t user_rsp);

thread_t* sched_get_current_thread() {
    thread_t* thread;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(thread));
    return thread;
}
void sched_set_current_thread(thread_t* thread) {
    __asm__ volatile("mov %0, %%gs:0" : : "r"(thread));
}

thread_t* find_next_thread() {
    thread_t* current_thread = sched_get_current_thread();

    while(true) {
        current_thread = (thread_t*) current_thread->thread_common.sched_next;
        if(current_thread == nullptr) {
            current_thread = g_scheduler.thread_head;
        }
        if(current_thread->thread_common.status == THREAD_STATUS_READY) {
            return current_thread;
        }
    }

    __builtin_unreachable();
}

void sched_yield() {
    uint64_t __spin_flag = spinlock_critical_lock(&g_scheduler.sched_lock);
    thread_t* current_thread = sched_get_current_thread();
    thread_t* next_thread = find_next_thread();
    assert(next_thread != nullptr && "No next thread found in sched_yield");

    // if(next_thread == current_thread) {
    //     spinlock_critical_unlock(&g_scheduler.sched_lock, __spin_flag);
    //     return;
    // }

    if(next_thread->thread_common.tid != 0) {
        next_thread->thread_common.status = THREAD_STATUS_RUNNING;
    }

    current_thread->thread_common.status = THREAD_STATUS_READY;

    sched_set_current_thread(next_thread);
    vm_address_space_switch(next_thread->thread_common.address_space);

    spinlock_critical_unlock(&g_scheduler.sched_lock, __spin_flag);

    __context_switch(current_thread, next_thread);
}


void sched_add_thread(thread_t* thread) {
    uint64_t __spin_flag = spinlock_critical_lock(&g_scheduler.sched_lock);

    if(g_scheduler.thread_head == nullptr) {
        g_scheduler.thread_head = thread;
        thread->thread_common.sched_next = nullptr;
    } else {
        thread_t* current = g_scheduler.thread_head;
        while(current->thread_common.sched_next != nullptr) {
            current = (thread_t*) current->thread_common.sched_next;
        }
        current->thread_common.sched_next = (struct thread*) thread;
        thread->thread_common.sched_next = nullptr;
    }

    spinlock_critical_unlock(&g_scheduler.sched_lock, __spin_flag);
}

void sched_remove_thread(thread_t* thread) {
    uint64_t __spin_flag = spinlock_critical_lock(&g_scheduler.sched_lock);

    if(g_scheduler.thread_head == thread) {
        g_scheduler.thread_head = (thread_t*) thread->thread_common.sched_next;
    } else {
        thread_t* current = g_scheduler.thread_head;
        while(current != nullptr && current->thread_common.sched_next != (struct thread*) thread) {
            current = (thread_t*) current->thread_common.sched_next;
        }
        if(current != nullptr) {
            current->thread_common.sched_next = thread->thread_common.sched_next;
        }
    }

    thread->thread_common.sched_next = nullptr;
    spinlock_critical_unlock(&g_scheduler.sched_lock, __spin_flag);
}
