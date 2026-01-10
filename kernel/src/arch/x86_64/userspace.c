#include <arch/cpu_local.h>
#include <arch/gdt.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/cpu_local.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <stdint.h>
#include <stdio.h>

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

const char* convert_syscall_number(syscall_nr_t nr) {
    switch(nr) {
        case SYS_EXIT:           return "SYS_EXIT";
        case SYS_CAP_PORT_GRANT: return "SYS_CAP_PORT_GRANT";
        default:                 return "UNKNOWN_SYSCALL";
    }
}

const char* convert_syscall_error(syscall_err_t err) {
    if(err > 0) {
        return "SUCCESS";
    }
    switch (err) {
        case SYSCALL_ERR_INVALID_ARGUMENT: return "SYSCALL_ERR_INVALID_ARGUMENT";
        case SYSCALL_INVALID_SYSCALL:      return "SYSCALL_INVALID_SYSCALL";
        default:                           return "UNKNOWN_SYSCALL_ERROR";
    }
}

syscall_err_t syscall_sys_exit() {
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    if(thread->thread_common.process) {
        process_destroy(thread->thread_common.process);
    }
    sched_yield_status(THREAD_STATUS_TERMINATED);
    return 0;
}

syscall_err_t syscall_sys_cap_port_grant(uint16_t start_port, uint16_t num_ports) {
    thread_t* thread = CPU_LOCAL_READ(current_thread);

    if((start_port + num_ports) < 65535) {
        return -SYSCALL_ERR_INVALID_ARGUMENT;
    }

    for(size_t i = start_port; i < start_port + num_ports; i++) {
        thread->thread_common.process->io_perm_map[thread->thread_common.process->io_perm_map_num++] = (uint16_t) i;
        tss_io_allow_port(CPU_LOCAL_READ(cpu_tss), i);
    }

    if(num_ports == 1) {
        printf("Granted I/O port 0x%llx to process %d\n", start_port, thread->thread_common.process->pid);
    } else {
        printf("Granted I/O port range 0x%llx-0x%llx to process %d\n", start_port, start_port + num_ports - 1, thread->thread_common.process->pid);
    }
    return 0;
}

syscall_err_t dispatch_syscall(syscall_nr_t syscall_nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    printf("syscall! 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n", syscall_nr, arg1, arg2, arg3, arg4, arg5);

    switch(syscall_nr) {
        case SYS_EXIT:           return syscall_sys_exit();
        case SYS_CAP_PORT_GRANT: return syscall_sys_cap_port_grant((uint16_t) arg1, (uint16_t) arg2);
        default:                 printf("Unknown syscall number: 0x%llx\n", syscall_nr); break;
    }

    return -SYSCALL_INVALID_SYSCALL;
}
