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

typedef syscall_err_t (*fn_syscall_handler0_t)();
typedef syscall_err_t (*fn_syscall_handler1_t)(uint64_t);
typedef syscall_err_t (*fn_syscall_handler2_t)(uint64_t, uint64_t);
typedef syscall_err_t (*fn_syscall_handler3_t)(uint64_t, uint64_t, uint64_t);
typedef syscall_err_t (*fn_syscall_handler4_t)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef syscall_err_t (*fn_syscall_handler5_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

typedef struct {
    size_t num_params;
    union {
        fn_syscall_handler0_t handler0;
        fn_syscall_handler1_t handler1;
        fn_syscall_handler2_t handler2;
        fn_syscall_handler3_t handler3;
        fn_syscall_handler4_t handler4;
        fn_syscall_handler5_t handler5;
    } handlers;
} syscall_entry_t;

syscall_entry_t syscall_table[256];


const char* convert_syscall_number(syscall_nr_t nr) {
    switch(nr) {
        case SYS_EXIT:           return "SYS_EXIT";
        case SYS_CAP_PORT_GRANT: return "SYS_CAP_PORT_GRANT";
        default:                 return "UNKNOWN_SYSCALL";
    }
}

const char* convert_syscall_error(syscall_err_t err) {
    if(err >= 0) {
        return "SUCCESS";
    }
    switch(err) {
        case SYSCALL_ERR_INVALID_ARGUMENT: return "SYSCALL_ERR_INVALID_ARGUMENT";
        case SYSCALL_ERR_INVALID_SYSCALL:  return "SYSCALL_ERR_INVALID_SYSCALL";
        default:                           return "UNKNOWN_SYSCALL_ERROR";
    }
}

#define SYSCALL_ASSERT_PARAM(cond)               \
    do {                                         \
        if(!(cond)) {                            \
            return SYSCALL_ERR_INVALID_ARGUMENT; \
        }                                        \
    } while(0)

syscall_err_t syscall_sys_exit(uint64_t exit_code) {
    (void) exit_code;
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    if(thread->thread_common.process) {
        process_destroy(thread->thread_common.process);
    }
    sched_yield_status(THREAD_STATUS_TERMINATED);
    return 0;
}

syscall_err_t syscall_sys_cap_port_grant(uint64_t start_port, uint64_t num_ports) {
    SYSCALL_ASSERT_PARAM(start_port + num_ports < 65535);
    thread_t* thread = CPU_LOCAL_READ(current_thread);

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

syscall_err_t syscall_sys_invalid(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    (void) arg0;
    (void) arg1;
    (void) arg2;
    (void) arg3;
    (void) arg4;
    return SYSCALL_ERR_INVALID_SYSCALL;
}


syscall_err_t dispatch_syscall(syscall_nr_t syscall_nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    thread_t* thread = CPU_LOCAL_READ(current_thread);

    if(syscall_nr >= 256) {
        printf(
            "[systrace] %d:%d - %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s\n",
            thread->thread_common.process->pid,
            thread->thread_common.tid,
            convert_syscall_number(syscall_nr),
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            convert_syscall_error(SYSCALL_ERR_INVALID_SYSCALL)
        );
        return SYSCALL_ERR_INVALID_SYSCALL;
    }

    syscall_entry_t entry = syscall_table[syscall_nr];
    assert(entry.num_params <= 5 && "syscall entry has too many parameters");
    switch(entry.num_params) {
        case 0: {
            syscall_err_t x = entry.handlers.handler0();
            printf("[systrace] %d:%d - (0x%llx) %s() = %s\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), convert_syscall_error(x));
            return x;
        }
        case 1: {
            syscall_err_t x = entry.handlers.handler1(arg1);
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx) = %s\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, convert_syscall_error(x));
            return x;
        }
        case 2: {
            syscall_err_t x = entry.handlers.handler2(arg1, arg2);
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx) = %s\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2, convert_syscall_error(x));
            return x;
        }
        case 3: {
            syscall_err_t x = entry.handlers.handler3(arg1, arg2, arg3);
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx) = %s\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2, arg3, convert_syscall_error(x));
            return x;
        }
        case 4: {
            syscall_err_t x = entry.handlers.handler4(arg1, arg2, arg3, arg4);
            printf(
                "[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s\n",
                thread->thread_common.process->pid,
                thread->thread_common.tid,
                syscall_nr,
                convert_syscall_number(syscall_nr),
                arg1,
                arg2,
                arg3,
                arg4,
                convert_syscall_error(x)
            );
            return x;
        }
        case 5: {
            syscall_err_t x = entry.handlers.handler5(arg1, arg2, arg3, arg4, arg5);
            printf(
                "[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s\n",
                thread->thread_common.process->pid,
                thread->thread_common.tid,
                syscall_nr,
                convert_syscall_number(syscall_nr),
                arg1,
                arg2,
                arg3,
                arg4,
                arg5,
                convert_syscall_error(x)
            );
            return x;
        }
        default: __builtin_unreachable();
    }
}


void userspace_init() {
    uint64_t efer = __rdmsr(IA32_EFER);
    efer |= (1 << 0);
    __wrmsr(IA32_EFER, efer);

    uint64_t star = ((uint64_t) (0x18 | 3) << 48) | ((uint64_t) 0x08 << 32);
    __wrmsr(IA32_STAR, star);

    __wrmsr(IA32_LSTAR, (uint64_t) __handle_syscall);
    __wrmsr(IA32_SFMASK, ~0x2);

    for(size_t i = 0; i < 256; i++) {
        syscall_table[i].num_params = 5;
        syscall_table[i].handlers.handler5 = syscall_sys_invalid;
    }

    syscall_table[SYS_EXIT].num_params = 1;
    syscall_table[SYS_EXIT].handlers.handler1 = syscall_sys_exit;

    syscall_table[SYS_CAP_PORT_GRANT].num_params = 2;
    syscall_table[SYS_CAP_PORT_GRANT].handlers.handler2 = syscall_sys_cap_port_grant;
}
