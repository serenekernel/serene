#include <common/userspace.h>
#include <memory/memobj.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/cpu_local.h>

syscall_err_t syscall_sys_exit(uint64_t exit_code) {
    (void) exit_code;
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    if(thread->thread_common.process) {
        process_destroy(thread->thread_common.process);
    }
    sched_yield_status(THREAD_STATUS_TERMINATED);
    return 0;
}
