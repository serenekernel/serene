#include <arch/cpu_local.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/arch.h>

syscall_ret_t syscall_sys_wait_for(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    SYSCALL_ASSERT_HANDLE(handle);

    SYSCALL_ASSERT_PARAM(handle_meta->owner_thread == current_thread->thread_common.tid);
    current_thread->thread_common.block_reason = THREAD_BLOCK_REASON_WAIT_HANDLE;
    current_thread->thread_common.status_data.blocked.wait_handle = handle;
    sched_yield_status(THREAD_STATUS_BLOCKED);
    return SYSCALL_RET_VALUE(0);
}
