#include "memory/vmm.h"

#include <arch/cpu_local.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/requests.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <string.h>

syscall_ret_t syscall_sys_endpoint_create() {
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    endpoint_t* endpoint = endpoint_create(thread, 16);

    handle_t handle = handle_create(HANDLE_TYPE_ENDPOINT, thread->thread_common.process->pid, HANDLE_CAPS_ENDPOINT_SEND | HANDLE_CAPS_ENDPOINT_RECEIVE | HANDLE_CAPS_ENDPOINT_CLOSE, (void*) endpoint);
    printf("Created endpoint handle 0x%llx for process %d\n", handle, thread->thread_common.process->pid);

    return SYSCALL_RET_VALUE(handle);
}

syscall_ret_t syscall_sys_endpoint_send(uint64_t handle_value, uint64_t payload, uint64_t payload_length, uint64_t reply_handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    endpoint_t* endpoint = (endpoint_t*) handle_meta->data;
    SYSCALL_ASSERT_PARAM(endpoint != NULL);
    SYSCALL_ASSERT_PARAM(handle_meta->capabilities & HANDLE_CAPS_ENDPOINT_SEND);
    SYSCALL_ASSERT_PARAM(payload_length < PAGE_SIZE_DEFAULT * 4);

    handle_t transferred_reply_handle = (handle_t) -1;
    if(reply_handle_value != (uint64_t) -1) {
        printf("reply_handle_value: 0x%llx\n", reply_handle_value);
        handle_meta_t* reply_handle_meta = handle_get((handle_t) reply_handle_value);
        SYSCALL_ASSERT_PARAM(reply_handle_meta != NULL);
        printf("reply_handle owner_pid: %u, current_pid: %u\n", reply_handle_meta->owner_pid, CPU_LOCAL_READ(current_thread)->thread_common.process->pid);
        SYSCALL_ASSERT_PARAM(reply_handle_meta->owner_pid == CPU_LOCAL_READ(current_thread)->thread_common.process->pid);
        SYSCALL_ASSERT_PARAM(reply_handle_meta->capabilities & HANDLE_CAPS_ENDPOINT_RECEIVE);

        // Duplicate the handle and transfer ownership to the receiving process
        transferred_reply_handle = handle_dup((handle_t) reply_handle_value);
        printf("duplicated reply_handle: 0x%llx, transferring to pid %u\n", transferred_reply_handle, endpoint->owner->thread_common.process->pid);
        handle_set_owner(transferred_reply_handle, endpoint->owner->thread_common.process->pid);
        handle_meta_t* check = handle_get(transferred_reply_handle);
        printf("after transfer, new handle owner_pid: %u\n", check ? check->owner_pid : 0);
    }

    thread_t* thread = CPU_LOCAL_READ(current_thread);
    printf("payload len: %lld\n", payload_length);
    ENTER_ADDRESS_SWITCH();
    ENTER_UAP_SECTION();

    vm_address_space_switch(endpoint->owner->thread_common.address_space);

    message_t* message = (message_t*) vmm_alloc_object(endpoint->owner->thread_common.address_space, sizeof(message_t) + payload_length);
    message->length = (uint32_t) payload_length;
    message->sender_pid = thread->thread_common.process->pid;
    message->reply_handle = transferred_reply_handle;

    printf("send: message ptr 0x%llx, length %u, sender_pid %u, reply_handle 0x%llx\n", (uint64_t) message, message->length, message->sender_pid, message->reply_handle);

    EXIT_UAP_SECTION()
    EXIT_ADDRESS_SWITCH();

    memcpy_um_um_unaligned(endpoint->owner->thread_common.address_space, thread->thread_common.address_space, (virt_addr_t) message->payload, (virt_addr_t) payload, payload_length);

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
    return SYSCALL_RET_VALUE(0);
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

    // Switch to receiver's address space to read message fields for debug
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    ENTER_ADDRESS_SWITCH();
    ENTER_UAP_SECTION();
    vm_address_space_switch(thread->thread_common.address_space);

    printf("receive: message ptr 0x%llx, length %u, sender_pid %u, reply_handle 0x%llx\n", (uint64_t) message, message->length, message->sender_pid, message->reply_handle);

    EXIT_UAP_SECTION();
    EXIT_ADDRESS_SWITCH();

    // Return the pointer directly - user can read length from message_t->length
    return SYSCALL_RET_VALUE((uint64_t) message);
}
