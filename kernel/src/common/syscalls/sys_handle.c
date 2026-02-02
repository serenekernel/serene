#include <arch/cpu_local.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <memory/memobj.h>

syscall_ret_t syscall_sys_wait_for(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    SYSCALL_ASSERT_HANDLE(handle);

    SYSCALL_ASSERT_PARAM(handle_meta->owner_pid == current_thread->thread_common.process->pid);
    current_thread->thread_common.block_reason = THREAD_BLOCK_REASON_WAIT_HANDLE;
    current_thread->thread_common.status_data.blocked.wait_handle = handle;
    sched_yield_status(THREAD_STATUS_BLOCKED);
    return SYSCALL_RET_VALUE(0);
}

syscall_ret_t syscall_sys_handle_dup(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    SYSCALL_ASSERT_HANDLE(handle);
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    handle_t new_handle = handle_dup(handle);
    handle_set_owner(new_handle, thread->thread_common.process->pid);
    printf("Duplicated handle 0x%llx to new handle 0x%llx for process %d\n", handle, new_handle, thread->thread_common.process->pid);
    return SYSCALL_RET_VALUE(new_handle);
}

syscall_ret_t syscall_sys_handle_close(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    SYSCALL_ASSERT_HANDLE(handle);
    handle_delete(handle);
    return SYSCALL_RET_VALUE(0);
}

syscall_ret_t syscall_sys_handle_get_owner(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    SYSCALL_ASSERT_HANDLE(handle);
    uint32_t owner_pid = handle_get_owner(handle);
    return SYSCALL_RET_VALUE(owner_pid);
}

syscall_ret_t syscall_sys_handle_set_owner(uint64_t handle_value, uint64_t owner_pid_value) {
    handle_t handle = *(handle_t*) &handle_value;
    SYSCALL_ASSERT_HANDLE(handle);
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_PARAM(handle_meta->capabilities & HANDLE_CAPS_OWNER_CHANGE);

    handle_set_owner(handle, (uint32_t) owner_pid_value);
    return SYSCALL_RET_VALUE(0);
}
