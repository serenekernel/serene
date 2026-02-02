#include <arch/cpu_local.h>
#include <arch/hardware/fpu.h>
#include <arch/hardware/lapic.h>
#include <arch/internal/gdt.h>
#include <arch/interrupts.h>
#include <arch/msr.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/handle.h>
#include <common/interrupts.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <common/thread.h>
#include <memory/memory.h>
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
    uint64_t return_addr; // Points to __userspace_init
    uint64_t entry_point; // loaded into rcx for the sysret
    uint64_t user_rsp; // user stack pointer used by __userspace_init
} __attribute__((packed)) userspace_init_frame_t;


extern void __jump_to_idle_thread(virt_addr_t stack_ptr, virt_addr_t entry_point);
extern void __context_switch(thread_t* old_thread, thread_t* new_thread, thread_status_t old_thread_status);
extern void __userspace_init_sysexit();
extern void __userspace_init_fred();

void sched_preempt_handler(interrupt_frame_t* frame) {
    (void) frame;
    lapic_eoi();
    sched_yield();
}


void sched_arch_init_bsp() {
    register_interrupt_handler(0x20, sched_preempt_handler);
}


void sched_arch_init_thread(thread_t* thread, virt_addr_t entry_point) {
    if(thread->thread_common.address_space->is_user) {
        userspace_init_frame_t* frame = (userspace_init_frame_t*) (thread->kernel_rsp - sizeof(userspace_init_frame_t));
        frame->r15 = 0;
        frame->r14 = 0;
        frame->r13 = 0;
        frame->r12 = 0;
        frame->rbp = 0;
        frame->rbx = 0;

        if(x86_64_fred_enabled()) {
            frame->return_addr = (virt_addr_t) __userspace_init_fred;
        } else {
            frame->return_addr = (virt_addr_t) __userspace_init_sysexit;
        }

        frame->entry_point = entry_point;
        frame->user_rsp = thread->thread_rsp;

        thread->kernel_rsp = (virt_addr_t) frame;
    } else {
        kernel_context_frame_t* frame = (kernel_context_frame_t*) (thread->kernel_rsp - sizeof(kernel_context_frame_t));
        frame->r15 = 0;
        frame->r14 = 0;
        frame->r13 = 0;
        frame->r12 = 0;
        frame->rbp = 0;
        frame->rbx = 0;
        frame->return_addr = entry_point;

        thread->kernel_rsp = (virt_addr_t) frame;
    }
}

void sched_arch_yield_prepare(thread_t* current_thread, thread_t* next_thread) {
    // @todo: what the fuck...
    x86_64_set_rsp0_stack(next_thread->kernel_rsp);

    // if we aren't comming from a process or that process has no ioports then no need to clear the map it's already empty
    if(current_thread->thread_common.process != nullptr && current_thread->thread_common.process->io_perm_map_num != 0) {
        tss_io_clear(CPU_LOCAL_READ(cpu_tss));
    }

    if(next_thread->thread_common.process != nullptr) {
        for(size_t i = 0; i < next_thread->thread_common.process->io_perm_map_num; i++) {
            tss_io_allow_port(CPU_LOCAL_READ(cpu_tss), next_thread->thread_common.process->io_perm_map[i]);
        }
    }

    __wrmsr(IA32_FS_BASE_MSR, 0xdeadbeef);
    __wrmsr(IA32_KERNEL_GS_BASE_MSR, 0xcafebabe);
}
