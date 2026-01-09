#include "arch/cpu_local.h"
#include "arch/hardware/lapic.h"
#include "common/arch.h"
#include "common/interrupts.h"

#include <arch/interrupts.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/cpu_local.h>
#include <common/memory.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <memory/vmm.h>
#include <stdint.h>

typedef struct {
    spinlock_t sched_lock;
    thread_t* idle_thread;
    thread_t* reaper_thread;
    thread_t* thread_head;
} scheduler_t;

scheduler_t g_scheduler;

void idle_thread() {
    while(1) {
        arch_pause();
    }
}

void reaper_thread() {
    while(1) {
        uint64_t __spin_flags = spinlock_critical_lock(&g_scheduler.sched_lock);
        thread_t* prev = nullptr;
        thread_t* current = g_scheduler.thread_head;

        while(current != nullptr) {
            if(current->thread_common.status == THREAD_STATUS_TERMINATED) {
                thread_t* to_reap = current;

                printf("[REAPER] Found terminated thread TID %u (reaping=%p)\n",
                       to_reap->thread_common.tid, (void*)to_reap);

                if(prev != nullptr) {
                    prev->thread_common.sched_next = current->thread_common.sched_next;
                    current = (thread_t*) current->thread_common.sched_next;
                } else {
                    g_scheduler.thread_head = (thread_t*) current->thread_common.sched_next;
                    current = g_scheduler.thread_head;
                }

                printf("to_reap->thread_rsp: 0x%llx\n", to_reap->thread_rsp);
                printf("to_reap->syscall_rsp: 0x%llx\n", to_reap->syscall_rsp);
                printf("to_reap->kernel_rsp: 0x%llx\n", to_reap->kernel_rsp);
                printf("to_reap: 0x%llx\n", to_reap);

                vmm_free(&kernel_allocator, to_reap->thread_rsp);
                vmm_free(&kernel_allocator, to_reap->syscall_rsp);
                vmm_free(&kernel_allocator, to_reap->kernel_rsp);
                vmm_free(&kernel_allocator, (virt_addr_t) to_reap);
            } else {
                prev = current;
                current = (thread_t*) current->thread_common.sched_next;
            }
        }

        spinlock_critical_unlock(&g_scheduler.sched_lock, __spin_flags);
        sched_yield();
    }
}

void sched_preempt_handler(interrupt_frame_t* frame) {
    (void) frame;
    lapic_eoi();
    sched_yield();
}

static uint32_t next_tid = 1;
extern void __jump_to_idle_thread(virt_addr_t stack_ptr, virt_addr_t entry_point);

void sched_init_bsp() {
    g_scheduler.sched_lock = 0;
    g_scheduler.idle_thread = sched_thread_kernel_init((virt_addr_t) idle_thread);
    g_scheduler.idle_thread->thread_common.tid = 1;

    g_scheduler.reaper_thread = sched_thread_kernel_init((virt_addr_t) reaper_thread);

    g_scheduler.thread_head = g_scheduler.idle_thread;
    g_scheduler.thread_head->thread_common.sched_next = (struct thread*) g_scheduler.reaper_thread;
    printf("Scheduler initialized with idle thread TID %u and reaper thread TID %u\n", g_scheduler.idle_thread->thread_common.tid, g_scheduler.reaper_thread->thread_common.tid);
    CPU_LOCAL_WRITE(current_thread, g_scheduler.idle_thread);
    register_interrupt_handler(0x20, sched_preempt_handler);
}

void sched_start_bsp() {
    g_scheduler.idle_thread->thread_common.status = THREAD_STATUS_RUNNING;

    lapic_timer_oneshot_ms(10);
    printf("BSP jumping to idle thread...\n");
    __jump_to_idle_thread(g_scheduler.idle_thread->syscall_rsp, (virt_addr_t) idle_thread);

    __builtin_unreachable();
}

void sched_init_ap() {
    CPU_LOCAL_WRITE(current_thread, g_scheduler.idle_thread);
}

thread_t* sched_thread_kernel_init(virt_addr_t entry_point) {
    thread_t* thread = (thread_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    thread->thread_common.process = nullptr;
    thread->thread_common.tid = next_tid++;
    thread->thread_common.address_space = &kernel_allocator;
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
    *(--stack) = 0; // rbx
    *(--stack) = 0; // rbp
    *(--stack) = 0; // r12
    *(--stack) = 0; // r13
    *(--stack) = 0; // r14
    *(--stack) = 0; // r15
    thread->syscall_rsp = (virt_addr_t) stack;

    return thread;
}

void __context_switch(thread_t* old_thread, thread_t* new_thread, thread_status_t old_thread_status);
void __userspace_init();

thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point) {
    assert(address_space->kernel_paging_structures_base != 0 && "cr3 for task is 0");
    thread_t* thread = (thread_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    thread->thread_common.process = nullptr;
    thread->thread_common.tid = next_tid++;
    thread->thread_common.address_space = address_space;
    thread->thread_common.sched_next = nullptr;
    thread->thread_common.proc_next = nullptr;
    // @todo: we should prob move this into the userspace allocator
    thread->thread_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->syscall_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->kernel_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->thread_common.status = THREAD_STATUS_READY;

    uint64_t* stack = (uint64_t*) thread->syscall_rsp;
    *(--stack) = thread->thread_rsp; // user rsp (set by __userspace_init)
    *(--stack) = entry_point; // rcx (where sysret will jump to - set by __userspace_init)
    *(--stack) = (virt_addr_t) __userspace_init; // Return address
    *(--stack) = 0; // rbx
    *(--stack) = 0; // rbp
    *(--stack) = 0; // r12
    *(--stack) = 0; // r13
    *(--stack) = 0; // r14
    *(--stack) = 0; // r15
    thread->syscall_rsp = (virt_addr_t) stack;

    return thread;
}

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
    sched_yield_status(THREAD_STATUS_READY);
}

void sched_yield_status(thread_status_t new_status) {
    disable_interrupts();
    assert(new_status != THREAD_STATUS_RUNNING && "Tried to make thread running from already running context");
    spinlock_lock(&g_scheduler.sched_lock);
    thread_t* current_thread = sched_get_current_thread();
    thread_t* next_thread = find_next_thread();
    assert(next_thread != nullptr && "No next thread found in sched_yield");
    assert(next_thread->thread_common.status == THREAD_STATUS_READY && "Thread is not ready...");

    vm_address_space_switch(next_thread->thread_common.address_space);

    // @todo: what the fuck...
    tss_t* tss = CPU_LOCAL_READ(cpu_tss);
    tss->rsp0 = next_thread->kernel_rsp;

    sched_set_current_thread(next_thread);

    spinlock_unlock(&g_scheduler.sched_lock);
    lapic_timer_oneshot_ms(10);
    __context_switch(current_thread, next_thread, new_status);
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
