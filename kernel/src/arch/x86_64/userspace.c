#include "arch/gdt.h"
#include <arch/cpu_local.h>
#include <common/sched.h>
#include <common/process.h>
#include <arch/msr.h>
#include <arch/userspace.h>
#include <common/cpu_local.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
void __handle_syscall();

void userspace_init() {
    uint64_t efer = __rdmsr(IA32_EFER);
    efer |= (1 << 0);
    __wrmsr(IA32_EFER, efer);

    uint64_t star = ((uint64_t) (0x18 | 3) << 48) | ((uint64_t) 0x08 << 32);
    __wrmsr(IA32_STAR, star);

    __wrmsr(IA32_LSTAR, (uint64_t) __handle_syscall);
    __wrmsr(IA32_SFMASK, ~0x2);
}

void dispatch_syscall(uint64_t syscall_nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    printf("syscall! 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n", syscall_nr, arg1, arg2, arg3, arg4, arg5);
    if(syscall_nr == 0xcafebabe) {
        printf("task dies now!!\n");
        thread_t* thread = CPU_LOCAL_READ(current_thread);
        if(thread->thread_common.process) {
            process_destroy(thread->thread_common.process);
        }
        sched_yield_status(THREAD_STATUS_TERMINATED);
    } else if(syscall_nr == 0xdeadbeaf) {
        thread_t* thread = CPU_LOCAL_READ(current_thread);
        uint16_t start_port = (uint16_t)arg1;
        uint16_t num_ports = (uint16_t)arg2;
        assert((start_port + num_ports) < 65535 && "too many i/o ports requested");
        for(size_t i = start_port; i < start_port + num_ports; i++) {
            printf("Granted I/O port 0x%llx to process %d\n", arg1, thread->thread_common.process->pid);
            thread->thread_common.process->io_perm_map[thread->thread_common.process->io_perm_map_num++] = (uint16_t)i;
            tss_io_allow_port(CPU_LOCAL_READ(cpu_tss), i);
        }

    }
}
