#include "memory/vmm.h"

#include <arch/cpu_local.h>
#include <arch/gdt.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/handle.h>
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
        case SYS_EXIT:                  return "SYS_EXIT";
        case SYS_CAP_PORT_GRANT:        return "SYS_CAP_PORT_GRANT";
        case SYS_CAP_IPC_DISCOVERY:     return "SYS_CAP_IPC_DISCOVERY";
        case SYS_WAIT_FOR:              return "SYS_WAIT_FOR";
        case SYS_ENDPOINT_CREATE:       return "SYS_ENDPOINT_CREATE";
        case SYS_ENDPOINT_DESTROY:      return "SYS_ENDPOINT_DESTROY";
        case SYS_ENDPOINT_SEND:         return "SYS_ENDPOINT_SEND";
        case SYS_ENDPOINT_RECEIVE:      return "SYS_ENDPOINT_RECEIVE";
        case SYS_ENDPOINT_FREE_MESSAGE: return "SYS_ENDPOINT_FREE_MESSAGE";
        default:                        return "UNKNOWN_SYSCALL";
    }
}

const char* convert_syscall_error(syscall_err_t err) {
    if(err >= 0) {
        return "SUCCESS";
    }
    switch(err) {
        case SYSCALL_ERR_INVALID_ARGUMENT: return "SYSCALL_ERR_INVALID_ARGUMENT";
        case SYSCALL_ERR_INVALID_SYSCALL:  return "SYSCALL_ERR_INVALID_SYSCALL";
        case SYSCALL_ERR_INVALID_HANDLE:   return "SYSCALL_ERR_INVALID_HANDLE";
        case SYSCALL_ERR_WOULD_BLOCK:      return "SYSCALL_ERR_WOULD_BLOCK";
        default:                           return "UNKNOWN_SYSCALL_ERROR";
    }
}

bool check_handle(handle_t handle, thread_t* thread, handle_type_t expected_type) {
    // -1 and 0 are always invalid
    if(handle == 0 || handle == -1) {
        return false;
    }
    handle_meta_t* handle_meta = handle_get(handle);
    if(!handle_meta || !handle_meta->valid) {
        return false;
    }
    if(handle_meta->owner_thread != thread->thread_common.tid) {
        return false;
    }
    if(expected_type != HANDLE_TYPE_INVALID && handle_meta->type != expected_type) {
        return false;
    }
    return true;
}

#define SYSCALL_ASSERT_PARAM(cond)                           \
    do {                                                     \
        if(!(cond)) {                                        \
            printf("syscall assertion failed: %s\n", #cond); \
            return SYSCALL_ERR_INVALID_ARGUMENT;             \
        }                                                    \
    } while(0)

#define SYSCALL_ASSERT_HANDLE(handle)                                      \
    do {                                                                   \
        thread_t* __current_thread = CPU_LOCAL_READ(current_thread);       \
        if(!check_handle(handle, __current_thread, HANDLE_TYPE_INVALID)) { \
            printf("syscall handle assertion failed: %s\n", #handle);      \
            return SYSCALL_ERR_INVALID_HANDLE;                             \
        }                                                                  \
    } while(0)

#define SYSCALL_ASSERT_HANDLE_TYPE(handle, type)                      \
    do {                                                              \
        thread_t* __current_thread = CPU_LOCAL_READ(current_thread);  \
        if(!check_handle(handle, __current_thread, type)) {           \
            printf("syscall handle assertion failed: %s\n", #handle); \
            return SYSCALL_ERR_INVALID_HANDLE;                        \
        }                                                             \
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

syscall_err_t syscall_sys_cap_ipc_discovery() {    
    // @note: this sucks
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    thread_t* init_thread = sched_get_thread(1);
    handle_t target = (handle_t)1; // hard coding :3
    handle_t our_handle = handle_dup(target);
    handle_set_owner(our_handle, thread->thread_common.tid);
    return (syscall_err_t) our_handle;
}

syscall_err_t syscall_sys_endpoint_create() {
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    endpoint_t* endpoint = endpoint_create(thread, 16);

    handle_t handle = handle_create(HANDLE_TYPE_ENDPOINT, thread->thread_common.tid, HANDLE_CAPS_ENDPOINT_SEND | HANDLE_CAPS_ENDPOINT_RECEIVE | HANDLE_CAPS_ENDPOINT_CLOSE, (void*) endpoint);
    printf("Created endpoint handle 0x%llx for process %d\n", handle, thread->thread_common.process->pid);

    // @note: temp
    sched_wake_thread_id(4);

    return (syscall_err_t) handle;
}

syscall_err_t syscall_sys_endpoint_destroy(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    return 0;
}

syscall_err_t syscall_sys_endpoint_send(uint64_t handle_value, uint64_t payload, uint64_t payload_length) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    endpoint_t* endpoint = (endpoint_t*) handle_meta->data;
    SYSCALL_ASSERT_PARAM(endpoint != NULL);
    SYSCALL_ASSERT_PARAM(handle_meta->capabilities & HANDLE_CAPS_ENDPOINT_SEND);
    SYSCALL_ASSERT_PARAM(payload_length < PAGE_SIZE_DEFAULT * 4);

    thread_t* thread = CPU_LOCAL_READ(current_thread);

    vm_address_space_switch(endpoint->owner->thread_common.address_space);
    message_t* message = (message_t*) vmm_alloc_user_object(endpoint->owner->thread_common.address_space, sizeof(message_t) + payload_length);
    message->length = (uint32_t) payload_length;
    message->type = 0;
    message->flags = 0;
    message->reply_handle = -1;
    vm_address_space_switch(thread->thread_common.address_space);

    memcpy_um_um(endpoint->owner->thread_common.address_space, thread->thread_common.address_space, (virt_addr_t) message->payload, (virt_addr_t) payload, payload_length);

    bool result = endpoint_send(endpoint, message);
    if(!result) {
        return SYSCALL_ERR_WOULD_BLOCK;
    }

    return 0;
}

// @note: holy shit I can't even make a joke about at how unsafe this is
syscall_err_t syscall_sys_endpoint_free(uint64_t message_ptr) {
    message_t* message = (message_t*) message_ptr;
    vmm_free(&kernel_allocator, (virt_addr_t) message);
    return 0;
}

syscall_err_t syscall_sys_endpoint_receive(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    SYSCALL_ASSERT_HANDLE_TYPE(handle, HANDLE_TYPE_ENDPOINT);
    endpoint_t* endpoint = (endpoint_t*) handle_meta->data;
    SYSCALL_ASSERT_PARAM(endpoint != NULL);
    SYSCALL_ASSERT_PARAM(handle_meta->capabilities & HANDLE_CAPS_ENDPOINT_RECEIVE);

    message_t* message = endpoint_receive(endpoint);
    if(!message) {
        return SYSCALL_ERR_WOULD_BLOCK;
    }

    // Return the pointer directly - user can read length from message_t->length
    return (syscall_err_t) (uint64_t) message;
}

syscall_err_t syscall_sys_wait_for(uint64_t handle_value) {
    handle_t handle = *(handle_t*) &handle_value;
    handle_meta_t* handle_meta = handle_get(handle);
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    SYSCALL_ASSERT_HANDLE(handle);

    SYSCALL_ASSERT_PARAM(handle_meta->owner_thread == current_thread->thread_common.tid);
    current_thread->thread_common.block_reason = THREAD_BLOCK_REASON_WAIT_HANDLE;
    current_thread->thread_common.status_data.blocked.wait_handle = handle;
    sched_yield_status(THREAD_STATUS_BLOCKED);
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
            "[systrace] %d:%d - %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s (0x%llx)\n",
            thread->thread_common.process->pid,
            thread->thread_common.tid,
            convert_syscall_number(syscall_nr),
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            convert_syscall_error(SYSCALL_ERR_INVALID_SYSCALL),
            SYSCALL_ERR_INVALID_SYSCALL
        );
        return SYSCALL_ERR_INVALID_SYSCALL;
    }

    syscall_entry_t entry = syscall_table[syscall_nr];
    assert(entry.num_params <= 5 && "syscall entry has too many parameters");

    switch(entry.num_params) {
        case 0: {
            printf("[systrace] %d:%d - (0x%llx) %s()\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr));
            syscall_err_t x = entry.handlers.handler0();
            printf("[systrace, res] %d:%d - (0x%llx) %s() = %s (0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), convert_syscall_error(x), x);
            return x;
        }
        case 1: {
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1);
            syscall_err_t x = entry.handlers.handler1(arg1);
            printf("[systrace, res] %d:%d - (0x%llx) %s(0x%llx) = %s (0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, convert_syscall_error(x), x);
            return x;
        }
        case 2: {
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2);
            syscall_err_t x = entry.handlers.handler2(arg1, arg2);
            printf("[systrace, res] %d:%d - (0x%llx) %s(0x%llx, 0x%llx) = %s (0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2, convert_syscall_error(x), x);
            return x;
        }
        case 3: {
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2, arg3);
            syscall_err_t x = entry.handlers.handler3(arg1, arg2, arg3);
            printf(
                "[systrace, res] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx) = %s (0x%llx)\n",
                thread->thread_common.process->pid,
                thread->thread_common.tid,
                syscall_nr,
                convert_syscall_number(syscall_nr),
                arg1,
                arg2,
                arg3,
                convert_syscall_error(x),
                x
            );
            return x;
        }
        case 4: {
            printf("[systrace, res] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2, arg3, arg4);
            syscall_err_t x = entry.handlers.handler4(arg1, arg2, arg3, arg4);
            printf(
                "[systrace, res] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s (0x%llx)\n",
                thread->thread_common.process->pid,
                thread->thread_common.tid,
                syscall_nr,
                convert_syscall_number(syscall_nr),
                arg1,
                arg2,
                arg3,
                arg4,
                convert_syscall_error(x),
                x
            );
            return x;
        }
        case 5: {
            printf("[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr), arg1, arg2, arg3, arg4, arg5);
            syscall_err_t x = entry.handlers.handler5(arg1, arg2, arg3, arg4, arg5);
            printf(
                "[systrace, res] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s (0x%llx)\n",
                thread->thread_common.process->pid,
                thread->thread_common.tid,
                syscall_nr,
                convert_syscall_number(syscall_nr),
                arg1,
                arg2,
                arg3,
                arg4,
                arg5,
                convert_syscall_error(x),
                x
            );
            return x;
        }
        default: __builtin_unreachable();
    }
}

#define SYSCALL_DISPATCHER(nr, __handler, __num_params)           \
    syscall_table[nr].num_params = __num_params;                  \
    syscall_table[nr].handlers.handler##__num_params = __handler;

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

    SYSCALL_DISPATCHER(SYS_EXIT, syscall_sys_exit, 1);

    SYSCALL_DISPATCHER(SYS_CAP_PORT_GRANT, syscall_sys_cap_port_grant, 2);
    SYSCALL_DISPATCHER(SYS_CAP_IPC_DISCOVERY, syscall_sys_cap_ipc_discovery, 0);

    SYSCALL_DISPATCHER(SYS_WAIT_FOR, syscall_sys_wait_for, 1);

    SYSCALL_DISPATCHER(SYS_ENDPOINT_CREATE, syscall_sys_endpoint_create, 0);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_DESTROY, syscall_sys_endpoint_destroy, 1);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_SEND, syscall_sys_endpoint_send, 3);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_RECEIVE, syscall_sys_endpoint_receive, 1);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_FREE_MESSAGE, syscall_sys_endpoint_free, 1);
}
