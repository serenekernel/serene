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

void sched_preempt_handler(interrupt_frame_t* frame) {
    (void) frame;
    lapic_eoi();
    sched_yield();
}

extern void __jump_to_idle_thread(virt_addr_t stack_ptr, virt_addr_t entry_point);

void sched_arch_init_bsp() {
    register_interrupt_handler(0x20, sched_preempt_handler);
}

void __context_switch(thread_t* old_thread, thread_t* new_thread, thread_status_t old_thread_status);
void __userspace_init();

void sched_arch_thread_fpu_init(thread_t* thread) {
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

void sched_arch_init_thread(thread_t* thread, virt_addr_t entry_point) {
    if(thread->thread_common.address_space->is_user) {
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
    } else {
        kernel_context_frame_t* frame = (kernel_context_frame_t*)(thread->kernel_rsp - sizeof(kernel_context_frame_t));
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
}