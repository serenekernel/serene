#include <common/cpu_local.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <string.h>

syscall_ret_t syscall_sys_memobj_create(uint64_t size, uint64_t perms) {
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);

    SYSCALL_ASSERT_PARAM(size > 0 && size <= (1ULL << 30)); // Max 1GB per object
    SYSCALL_ASSERT_PARAM(perms <= (MEMOBJ_PERM_READ | MEMOBJ_PERM_WRITE | MEMOBJ_PERM_EXEC));

    memobj_t* memobj = memobj_create(size, (memobj_perms_t) perms);
    if(!memobj) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }

    handle_t handle = handle_create(HANDLE_TYPE_MEMOBJ, current_thread->thread_common.tid, HANDLE_CAPS_MEMOBJ_MAP | HANDLE_CAPS_MEMOBJ_DESTROY, (void*) memobj);

    printf("Created memobj id=%llu size=%zu perms=0x%llx, handle=0x%llx\n", memobj->id, memobj->size, perms, handle);
    return SYSCALL_RET_VALUE(handle);
}

syscall_ret_t syscall_sys_map(uint64_t process_handle_value, uint64_t memobj_handle_value, uint64_t vaddr, uint64_t perms, uint64_t flags) {
    handle_t process_handle = *(handle_t*) &process_handle_value;
    handle_t memobj_handle = *(handle_t*) &memobj_handle_value;

    SYSCALL_ASSERT_HANDLE_TYPE(process_handle, HANDLE_TYPE_PROCESS);
    SYSCALL_ASSERT_HANDLE_TYPE(memobj_handle, HANDLE_TYPE_MEMOBJ);

    handle_meta_t* process_meta = handle_get(process_handle);
    handle_meta_t* memobj_meta = handle_get(memobj_handle);

    SYSCALL_ASSERT_PARAM(process_meta->capabilities & HANDLE_CAPS_PROCESS_MAP);
    SYSCALL_ASSERT_PARAM(memobj_meta->capabilities & HANDLE_CAPS_MEMOBJ_MAP);

    process_t* target_process = (process_t*) process_meta->data;
    memobj_t* memobj = (memobj_t*) memobj_meta->data;

    SYSCALL_ASSERT_PARAM(target_process != NULL);
    SYSCALL_ASSERT_PARAM(memobj != NULL);

    if(!memobj_validate_perms((memobj_perms_t) perms, memobj->max_perms)) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_PERMISSION_DENIED);
    }

    virt_addr_t result_vaddr = memobj_map(target_process->address_space, memobj, (virt_addr_t) vaddr, (memobj_perms_t) perms, (memobj_map_flags_t) flags);

    if(result_vaddr == 0) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_ADDRESS_IN_USE);
    }

    return SYSCALL_RET_VALUE(result_vaddr);
}

syscall_ret_t syscall_sys_copy_to(uint64_t process_handle_value, uint64_t dst, uint64_t src, uint64_t size) {
    handle_t process_handle = *(handle_t*) &process_handle_value;

    SYSCALL_ASSERT_HANDLE_TYPE(process_handle, HANDLE_TYPE_PROCESS);

    handle_meta_t* process_meta = handle_get(process_handle);
    SYSCALL_ASSERT_PARAM(process_meta->capabilities & HANDLE_CAPS_PROCESS_COPY);

    process_t* target_process = (process_t*) process_meta->data;
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);

    SYSCALL_ASSERT_PARAM(target_process != NULL);
    SYSCALL_ASSERT_PARAM(size > 0 && size <= (4 * PAGE_SIZE_DEFAULT));

    memcpy_um_um_unaligned(target_process->address_space, current_thread->thread_common.address_space, (virt_addr_t) dst, (virt_addr_t) src, size);

    return SYSCALL_RET_VALUE(0);
}
