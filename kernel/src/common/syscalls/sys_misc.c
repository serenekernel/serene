#include "common/arch.h"

#include <common/cpu_local.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <memory/memobj.h>

syscall_ret_t syscall_sys_exit(uint64_t exit_code) {
    (void) exit_code;
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    if(thread->thread_common.process) {
        process_destroy(thread->thread_common.process);
    }
    printf("Process %d exiting with code %d\n", thread->thread_common.process ? thread->thread_common.process->pid : -1, exit_code);
    sched_yield_status(THREAD_STATUS_TERMINATED);
    return SYSCALL_RET_VALUE(0);
}

// @note: temporary syscall for testing purposes, will be removed in the future
syscall_ret_t syscall_sys_msg(const char* msg, size_t length) {
    if(!validate_user_buffer_current_process(msg, length)) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_ARGUMENT);
    }

    ENTER_UAP_SECTION();
    printf("%.*s", (int) length, msg);
    EXIT_UAP_SECTION();
    return SYSCALL_RET_VALUE(0);
}
