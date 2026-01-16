#include <arch/cpu_local.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <string.h>


syscall_ret_t syscall_sys_process_create_empty() {
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    
    process_t* new_process = process_create();
    if (!new_process) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }
    
    handle_t handle = handle_create(
        HANDLE_TYPE_PROCESS,
        current_thread->thread_common.tid,
        HANDLE_CAPS_PROCESS_MAP | HANDLE_CAPS_PROCESS_COPY | 
        HANDLE_CAPS_PROCESS_START | HANDLE_CAPS_PROCESS_DESTROY,
        (void*) new_process
    );
    
    printf("Created empty process %d, handle=0x%llx\n", new_process->pid, handle);
    return SYSCALL_RET_VALUE(handle);
}

syscall_ret_t syscall_sys_start(uint64_t process_handle_value, uint64_t entry) {
    handle_t process_handle = *(handle_t*) &process_handle_value;
    
    SYSCALL_ASSERT_HANDLE_TYPE(process_handle, HANDLE_TYPE_PROCESS);
    
    handle_meta_t* process_meta = handle_get(process_handle);
    SYSCALL_ASSERT_PARAM(process_meta->capabilities & HANDLE_CAPS_PROCESS_START);
    
    process_t* target_process = (process_t*) process_meta->data;
    SYSCALL_ASSERT_PARAM(target_process != NULL);
    SYSCALL_ASSERT_PARAM(entry != 0);
    
    // @todo: validate that entry is executable
    // for now we just trust them, trust the caller
    thread_t* thread = sched_thread_user_init(
        target_process->address_space,
        (virt_addr_t) entry
    );
    
    if (!thread) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }
    
    process_add_thread(target_process, thread);
    sched_add_thread(thread);    
    
    printf("Started process %d at entry=0x%llx\n",
           target_process->pid, entry);
    
    return SYSCALL_RET_VALUE(0);
}
