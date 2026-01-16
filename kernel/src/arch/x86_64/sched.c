#include <arch/cpu_local.h>
#include <arch/hardware/fpu.h>
#include <arch/internal/gdt.h>
#include <arch/hardware/lapic.h>
#include <common/arch.h>
#include <common/interrupts.h>
#include <common/thread.h>

#include <common/handle.h>
#include <arch/interrupts.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/cpu_local.h>
#include <memory/memory.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <memory/vmm.h>
#include <stdint.h>

typedef struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t return_addr;
} __attribute__((packed)) kernel_context_frame_t;

typedef struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t return_addr;  // Points to __userspace_init
    uint64_t entry_point;  // loaded into rcx for the sysret
    uint64_t user_rsp;     // user stack pointer used by __userspace_init
} __attribute__((packed)) userspace_init_frame_t;

typedef struct {
    thread_t* idle_thread;
    thread_t* reaper_thread;
    thread_t* thread_head;
} scheduler_t;

spinlock_t g_sched_lock = 0;
scheduler_t g_scheduler;

void idle_thread() {
    while(1) {
        arch_pause();
    }
}

extern process_t* g_proc_head;

void reaper_thread() {
    while(1) {
        uint64_t __spin_flags = spinlock_critical_lock(&g_sched_lock);
        {
            thread_t* prev = nullptr;
            thread_t* current = g_scheduler.thread_head;

            while(current != nullptr) {
                if(current->thread_common.happy_to_die) {
                    current->thread_common.status = THREAD_STATUS_TERMINATED;
                }
                if(current->thread_common.status == THREAD_STATUS_TERMINATED) {
                    thread_t* to_reap = current;

                    if(to_reap->thread_common.process != nullptr) {
                        printf("[REAPER] Found terminated thread TID %u PID %u (reaping=%p)\n", to_reap->thread_common.tid, to_reap->thread_common.process->pid, (void*) to_reap);
                        to_reap->thread_common.process->thread_count--;
                    } else {
                        printf("[REAPER] Found terminated thread TID %u PID <none> (reaping=%p)\n", to_reap->thread_common.tid, (void*) to_reap);
                    }
                    if(prev != nullptr) {
                        prev->sched_next = current->sched_next;
                        current = (thread_t*) current->sched_next;
                    } else {
                        g_scheduler.thread_head = (thread_t*) current->sched_next;
                        current = g_scheduler.thread_head;
                    }

                    printf("to_reap->thread_rsp: 0x%llx\n", to_reap->thread_rsp);
                    printf("to_reap->kernel_rsp: 0x%llx\n", to_reap->kernel_rsp);
                    printf("to_reap: 0x%llx\n", to_reap);

                    vmm_free(to_reap->thread_common.address_space, to_reap->thread_rsp);
                    vmm_free(&kernel_allocator, to_reap->kernel_rsp);
                    vmm_free(&kernel_allocator, (virt_addr_t) to_reap);
                } else {
                    prev = current;
                    current = (thread_t*) current->sched_next;
                }
            }
        }
        {
            process_t* current = g_proc_head;
            while(current != nullptr) {
                if(current->happy_to_die && current->thread_count == 0) {
                    process_t* to_reap = current;
                    printf("[REAPER] Found terminated process PID %u (reaping=%p)\n", to_reap->pid, (void*) to_reap);

                    if(to_reap->prev != nullptr) {
                        to_reap->prev->next = to_reap->next;
                    }

                    if(to_reap->next != nullptr) {
                        to_reap->next->prev = to_reap->prev;
                    }

                    if(to_reap == g_proc_head) {
                        g_proc_head = (process_t*) to_reap->next;
                    }

                    current = (process_t*) to_reap->next;

                    vmm_destory_allocator(to_reap->address_space);
                    vmm_free(&kernel_allocator, (virt_addr_t) to_reap);
                    break; // restart from head
                } else {
                    current = (process_t*) current->next;
                }
            }
        }
        spinlock_critical_unlock(&g_sched_lock, __spin_flags);
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

thread_t* __sched_get_thread(uint32_t tid) {
    thread_t* current = g_scheduler.thread_head;
    while(current != nullptr) {
        if(current->thread_common.tid == tid) {
            return current;
        }
        current = (thread_t*) current->sched_next;
    }
    return nullptr;
}


thread_t* sched_get_thread(uint32_t tid) {
    uint64_t __irqflags = spinlock_critical_lock(&g_sched_lock);
    thread_t* res = __sched_get_thread(tid);
    spinlock_critical_unlock(&g_sched_lock, __irqflags);
    return res;
}

void sched_init_bsp() {
    g_sched_lock = 0;
    g_scheduler.idle_thread = sched_thread_kernel_init((virt_addr_t) idle_thread);
    g_scheduler.idle_thread->thread_common.tid = 1;

    g_scheduler.reaper_thread = sched_thread_kernel_init((virt_addr_t) reaper_thread);

    g_scheduler.thread_head = g_scheduler.idle_thread;
    g_scheduler.thread_head->sched_next = (struct thread*) g_scheduler.reaper_thread;
    printf("Scheduler initialized with idle thread TID %u and reaper thread TID %u\n", g_scheduler.idle_thread->thread_common.tid, g_scheduler.reaper_thread->thread_common.tid);
    CPU_LOCAL_WRITE(current_thread, g_scheduler.idle_thread);
    register_interrupt_handler(0x20, sched_preempt_handler);
}

void sched_start_bsp() {
    g_scheduler.idle_thread->thread_common.status = THREAD_STATUS_RUNNING;

    lapic_timer_oneshot_ms(10);
    printf("BSP jumping to idle thread...\n");
    __jump_to_idle_thread(g_scheduler.idle_thread->kernel_rsp, (virt_addr_t) idle_thread);

    __builtin_unreachable();
}

void sched_init_ap() {
    CPU_LOCAL_WRITE(current_thread, g_scheduler.idle_thread);
}


void __context_switch(thread_t* old_thread, thread_t* new_thread, thread_status_t old_thread_status);
void __userspace_init();

void thread_fpu_init(thread_t* thread) {
    bool __irq = interrupts_enabled();
    disable_interrupts();

    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    if(current_thread != nullptr && current_thread->fpu_area != nullptr) fpu_save(current_thread->fpu_area);
    fpu_load(thread->fpu_area);
    uint16_t x87cw = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (0b11 << 8);
    asm volatile("fldcw %0" : : "m"(x87cw) : "memory");
    uint32_t mxcsr = (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12);
    asm volatile("ldmxcsr %0" : : "m"(mxcsr) : "memory");
    fpu_save(thread->fpu_area);
    if(current_thread != nullptr && current_thread->fpu_area != nullptr) fpu_load(current_thread->fpu_area);

    if(__irq) enable_interrupts();
}

thread_t* sched_thread_kernel_init(virt_addr_t entry_point) {
    thread_t* thread = (thread_t*) vmm_alloc_backed(&kernel_allocator, ALIGN_UP(ALIGN_UP(sizeof(thread_t) + fpu_area_size(), 16), PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    thread->thread_common.process = nullptr;
    thread->thread_common.tid = next_tid++;
    thread->thread_common.address_space = &kernel_allocator;
    thread->fpu_area = nullptr;
    thread->sched_next = nullptr;
    thread->proc_next = nullptr;
    thread->thread_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->syscall_rsp = 0;
    thread->kernel_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->thread_common.status = THREAD_STATUS_READY;

    // Set up initial stack frame for context switch
    kernel_context_frame_t* frame = (kernel_context_frame_t*)(thread->kernel_rsp - sizeof(kernel_context_frame_t));
    frame->r15 = 0;
    frame->r14 = 0;
    frame->r13 = 0;
    frame->r12 = 0;
    frame->rbp = 0;
    frame->rbx = 0;
    frame->return_addr = entry_point;
    
    thread->kernel_rsp = (virt_addr_t) frame;

    return thread;
}

thread_t* sched_thread_user_init(vm_allocator_t* address_space, virt_addr_t entry_point) {
    assert(address_space->kernel_paging_structures_base != 0 && "cr3 for task is 0");
    thread_t* thread = (thread_t*) vmm_alloc_backed(&kernel_allocator, ALIGN_UP(ALIGN_UP(sizeof(thread_t) + fpu_area_size(), 64), PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    thread->thread_common.process = nullptr;
    thread->thread_common.tid = next_tid++;
    thread->thread_common.address_space = address_space;
    thread->fpu_area = (void*) ALIGN_UP((virt_addr_t) thread + sizeof(thread_t), 64);
    thread->sched_next = nullptr;
    thread->proc_next = nullptr;

    thread->thread_rsp = vmm_alloc_backed(address_space, 4, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE, false) + (4 * PAGE_SIZE_DEFAULT) - 8;
    thread->syscall_rsp = 0;
    thread->kernel_rsp = vmm_alloc_backed(&kernel_allocator, 4, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true) + (4 * PAGE_SIZE_DEFAULT);
    thread->thread_common.status = THREAD_STATUS_READY;
    thread_fpu_init(thread);

    // Set up initial stack frame for userspace thread initialization
    userspace_init_frame_t* frame = (userspace_init_frame_t*)(thread->kernel_rsp - sizeof(userspace_init_frame_t));
    frame->r15 = 0;
    frame->r14 = 0;
    frame->r13 = 0;
    frame->r12 = 0;
    frame->rbp = 0;
    frame->rbx = 0;
    frame->return_addr = (virt_addr_t) __userspace_init;
    frame->entry_point = entry_point;
    frame->user_rsp = thread->thread_rsp;
    
    thread->kernel_rsp = (virt_addr_t) frame;

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
        current_thread = (thread_t*) current_thread->sched_next;
        if(current_thread == nullptr) {
            current_thread = g_scheduler.thread_head;
        }
        if(current_thread->thread_common.status == THREAD_STATUS_READY) {
            if(current_thread->thread_common.happy_to_die) {
                current_thread->thread_common.status = THREAD_STATUS_TERMINATED;
                continue;
            }
            return current_thread;
        }
        if(current_thread->thread_common.status == THREAD_STATUS_BLOCKED) {
            if(current_thread->thread_common.block_reason == THREAD_BLOCK_REASON_WAIT_HANDLE) {
                handle_t wait_handle = current_thread->thread_common.status_data.blocked.wait_handle;
                if(handle_has_data(wait_handle)) {
                    current_thread->thread_common.status = THREAD_STATUS_READY;
                    return current_thread;
                }
            }
            continue;
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
    spinlock_lock(&g_sched_lock);
    thread_t* current_thread = sched_get_current_thread();
    thread_t* next_thread = find_next_thread();
    assert(next_thread != nullptr && "No next thread found in sched_yield");
    assert(next_thread->thread_common.status == THREAD_STATUS_READY && "Thread is not ready...");

    vm_address_space_switch(next_thread->thread_common.address_space);

    // @todo: what the fuck...
    tss_t* tss = CPU_LOCAL_READ(cpu_tss);
    tss->rsp0 = next_thread->kernel_rsp;

    // if we aren't comming from a process or that process has no ioports then no need to clear the map it's already empty
    if(current_thread->thread_common.process != nullptr && current_thread->thread_common.process->io_perm_map_num != 0) {
        tss_io_clear(CPU_LOCAL_READ(cpu_tss));
    }

    if(next_thread->thread_common.process != nullptr) {
        for(size_t i = 0; i < next_thread->thread_common.process->io_perm_map_num; i++) {
            tss_io_allow_port(CPU_LOCAL_READ(cpu_tss), next_thread->thread_common.process->io_perm_map[i]);
        }
    }

    if(current_thread->fpu_area != nullptr) {
        fpu_save(current_thread->fpu_area);
    }
    if(next_thread->fpu_area != nullptr) {
        fpu_load(next_thread->fpu_area);
    }

    sched_set_current_thread(next_thread);

    spinlock_unlock(&g_sched_lock);
    lapic_timer_oneshot_ms(10);
    __context_switch(current_thread, next_thread, new_status);
}

void sched_add_thread(thread_t* thread) {
    uint64_t __spin_flag = spinlock_critical_lock(&g_sched_lock);

    if(g_scheduler.thread_head == nullptr) {
        g_scheduler.thread_head = thread;
        thread->sched_next = nullptr;
    } else {
        thread_t* current = g_scheduler.thread_head;
        while(current->sched_next != nullptr) {
            current = (thread_t*) current->sched_next;
        }
        current->sched_next = (struct thread*) thread;
        thread->sched_next = nullptr;
    }

    spinlock_critical_unlock(&g_sched_lock, __spin_flag);
}

void sched_wake_thread_id(uint32_t thread) {
    bool enabled = interrupts_enabled();
    if(enabled) disable_interrupts();

    spinlock_lock(&g_sched_lock);

    thread_t* to_wake = __sched_get_thread(thread);
    assert(to_wake != nullptr && "Tried to wake a nonexistant thread");
    assert(to_wake->thread_common.status != THREAD_STATUS_TERMINATED && "Tried to wake a terminated thread");
    if(to_wake->thread_common.status == THREAD_STATUS_RUNNING) {
        spinlock_unlock(&g_sched_lock);
        printf("Woke thread TID %u\n", to_wake->thread_common.tid);
        if(enabled) enable_interrupts();
        return;
    }
    to_wake->thread_common.status = THREAD_STATUS_READY;
    printf("Woke thread TID %u\n", to_wake->thread_common.tid);
    spinlock_unlock(&g_sched_lock);
    if(enabled) enable_interrupts();
}

void sched_remove_thread(thread_t* thread) {
    uint64_t __spin_flag = spinlock_critical_lock(&g_sched_lock);

    if(g_scheduler.thread_head == thread) {
        g_scheduler.thread_head = (thread_t*) thread->sched_next;
    } else {
        thread_t* current = g_scheduler.thread_head;
        while(current != nullptr && current->sched_next != (struct thread*) thread) {
            current = (thread_t*) current->sched_next;
        }
        if(current != nullptr) {
            current->sched_next = thread->sched_next;
        }
    }

    thread->sched_next = nullptr;
    spinlock_critical_unlock(&g_sched_lock, __spin_flag);
}
