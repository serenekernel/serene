#include <arch/cpu_local.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <string.h>
#include <common/arch.h>

syscall_ret_t syscall_sys_endpoint_create() {
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    endpoint_t* endpoint = endpoint_create(thread, 16);

    handle_t handle = handle_create(HANDLE_TYPE_ENDPOINT, thread->thread_common.tid, HANDLE_CAPS_ENDPOINT_SEND | HANDLE_CAPS_ENDPOINT_RECEIVE | HANDLE_CAPS_ENDPOINT_CLOSE, (void*) endpoint);
    printf("Created endpoint handle 0x%llx for process %d\n", handle, thread->thread_common.process->pid);

    // @note: temp
    sched_wake_thread_id(4);

    return SYSCALL_RET_VALUE(handle);
}

syscall_ret_t syscall_sys_endpoint_destroy(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    handle_delete(handle);
    return SYSCALL_RET_VALUE(0);
}

syscall_ret_t syscall_sys_endpoint_send(uint64_t handle_value, uint64_t payload, uint64_t payload_length) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    endpoint_t* endpoint = (endpoint_t*) handle_meta->data;
    SYSCALL_ASSERT_PARAM(endpoint != NULL);
    SYSCALL_ASSERT_PARAM(handle_meta->capabilities & HANDLE_CAPS_ENDPOINT_SEND);
    SYSCALL_ASSERT_PARAM(payload_length < PAGE_SIZE_DEFAULT * 4);

    thread_t* thread = CPU_LOCAL_READ(current_thread);

    ENTER_UAP_SECTION();
    ENTER_WP_SECTION()
    ENTER_ADDRESS_SWITCH();

    vm_address_space_switch(endpoint->owner->thread_common.address_space);
    message_t* message = (message_t*) vmm_alloc_object(endpoint->owner->thread_common.address_space, sizeof(message_t) + payload_length);
    message->length = (uint32_t) payload_length;
    message->type = 0;
message->flags = 0;
    message->reply_handle = -1;
    memcpy_um_um(endpoint->owner->thread_common.address_space, thread->thread_common.address_space, (virt_addr_t) message->payload, (virt_addr_t) payload, payload_length);

    EXIT_ADDRESS_SWITCH();
    EXIT_WP_SECTION();
    EXIT_UAP_SECTION()

    bool result = endpoint_send(endpoint, message);
    if(!result) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_WOULD_BLOCK);
    }

    return SYSCALL_RET_VALUE(0);
}

syscall_ret_t syscall_sys_endpoint_free_message(uint64_t message_ptr) {
    message_t* message = (message_t*) message_ptr;
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    vmm_free(thread->thread_common.address_space, (virt_addr_t) message);
    return SYSCALL_RET_VALUE(0) ;
}

syscall_ret_t syscall_sys_endpoint_receive(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    endpoint_t* endpoint = (endpoint_t*) handle_meta->data;
    SYSCALL_ASSERT_PARAM(endpoint != NULL);
    SYSCALL_ASSERT_PARAM(handle_meta->capabilities & HANDLE_CAPS_ENDPOINT_RECEIVE);

    message_t* message = endpoint_receive(endpoint);
    if(!message) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_WOULD_BLOCK);
    }

    // Return the pointer directly - user can read length from message_t->length
    return SYSCALL_RET_VALUE((uint64_t) message);
}
