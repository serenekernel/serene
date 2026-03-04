#include "arch/msr.h"
#include "memory/memory.h"

#include <arch/cpu_local.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <stdint.h>
#include <string.h>


syscall_ret_t syscall_sys_process_create_empty() {
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);

    process_t* new_process = process_create();
    if(!new_process) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }

    handle_t handle = handle_create(HANDLE_TYPE_PROCESS, current_thread->thread_common.process->pid, HANDLE_CAPS_PROCESS_MAP | HANDLE_CAPS_PROCESS_COPY | HANDLE_CAPS_PROCESS_CREATE_THREAD | HANDLE_CAPS_PROCESS_DESTROY, (void*) new_process);

    printf("Created empty process %d, handle=0x%llx\n", new_process->pid, handle);
    return SYSCALL_RET_VALUE(handle);
}

syscall_ret_t syscall_sys_get_pid(uint64_t process_handle_value) {
    if(process_handle_value == 0) {
        thread_t* current_thread = CPU_LOCAL_READ(current_thread);
        return SYSCALL_RET_VALUE(current_thread->thread_common.process->pid);
    }

    handle_t process_handle = *(handle_t*) &process_handle_value;

    SYSCALL_ASSERT_HANDLE_TYPE(process_handle, HANDLE_TYPE_PROCESS);
    handle_meta_t* process_meta = handle_get(process_handle);

    process_t* target_process = (process_t*) process_meta->data;
    SYSCALL_ASSERT_PARAM(target_process != NULL);

    return SYSCALL_RET_VALUE(target_process->pid);
}

syscall_ret_t syscall_sys_create_thread(uint64_t process_handle_value, uint64_t entry, uint64_t stack) {
    handle_t process_handle = *(handle_t*) &process_handle_value;

    SYSCALL_ASSERT_HANDLE_TYPE(process_handle, HANDLE_TYPE_PROCESS);

    handle_meta_t* process_meta = handle_get(process_handle);
    SYSCALL_ASSERT_PARAM(process_meta->capabilities & HANDLE_CAPS_PROCESS_CREATE_THREAD);

    process_t* target_process = (process_t*) process_meta->data;
    SYSCALL_ASSERT_PARAM(target_process != NULL);
    SYSCALL_ASSERT_PARAM(entry != 0);

    printf("Creating thread in process PID %d with entry=0x%llx and stack=0x%llx\n", target_process->pid, entry, stack);
    thread_t* thread = sched_thread_user_init(target_process->address_space, (virt_addr_t) entry, stack);

    if(!thread) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }

    process_add_thread(target_process, thread);

    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    printf("Created thread TID %d in process PID %d with entry=0x%llx\n", thread->thread_common.tid, target_process->pid, entry);

    handle_t thread_handle = handle_create(HANDLE_TYPE_THREAD, current_thread->thread_common.process->pid, HANDLE_CAPS_THREAD_CREATE | HANDLE_CAPS_THREAD_START | HANDLE_CAPS_THREAD_DESTROY, (void*) thread);
    printf("Created handle 0x%llx for thread TID %d in process PID %d\n", thread_handle, thread->thread_common.tid, target_process->pid);

    return SYSCALL_RET_VALUE(thread_handle);
}


syscall_ret_t syscall_sys_start(uint64_t thread_handle_value) {
    handle_t thread_handle = *(handle_t*) &thread_handle_value;

    SYSCALL_ASSERT_HANDLE_TYPE(thread_handle, HANDLE_TYPE_THREAD);

    handle_meta_t* thread_meta = handle_get(thread_handle);
    SYSCALL_ASSERT_PARAM(thread_meta->capabilities & HANDLE_CAPS_THREAD_START);

    thread_t* target_thread = (thread_t*) thread_meta->data;
    SYSCALL_ASSERT_PARAM(target_thread != NULL);
    sched_start_thread(target_thread);

    return SYSCALL_RET_VALUE(0);
}

syscall_ret_t syscall_sys_set_fsbase(uint64_t fsbase) {
    __wrmsr(IA32_FS_BASE_MSR, fsbase);
    return SYSCALL_RET_VALUE(0);
}
