#include <arch/cpu_local.h>
#include <arch/internal/gdt.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/arch.h>
#include <common/config.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/syscalls/syscall.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <memory/vmm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void __handle_syscall();

typedef syscall_ret_t (*fn_syscall_handler0_t)();
typedef syscall_ret_t (*fn_syscall_handler1_t)(uint64_t);
typedef syscall_ret_t (*fn_syscall_handler2_t)(uint64_t, uint64_t);
typedef syscall_ret_t (*fn_syscall_handler3_t)(uint64_t, uint64_t, uint64_t);
typedef syscall_ret_t (*fn_syscall_handler4_t)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef syscall_ret_t (*fn_syscall_handler5_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef syscall_ret_t (*fn_syscall_handler6_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

typedef struct {
    size_t num_params;
    union {
        fn_syscall_handler0_t handler0;
        fn_syscall_handler1_t handler1;
        fn_syscall_handler2_t handler2;
        fn_syscall_handler3_t handler3;
        fn_syscall_handler4_t handler4;
        fn_syscall_handler5_t handler5;
        fn_syscall_handler6_t handler6;
    } handlers;
} syscall_entry_t;

#define MAX_SYSCALL_NUMBER 512

syscall_entry_t syscall_table[MAX_SYSCALL_NUMBER];


const char* convert_syscall_number(syscall_nr_t nr) {
    switch(nr) {
        case SYS_EXIT:                  return "SYS_EXIT";
        case SYS_PROCESS_CREATE_EMPTY:  return "SYS_PROCESS_CREATE_EMPTY";
        case SYS_PROCESS_THREAD_CREATE: return "SYS_PROCESS_THREAD_CREATE";
        case SYS_PROCESS_GET_PID:       return "SYS_PROCESS_GET_PID";
        case SYS_START:                 return "SYS_START";
        case SYS_MEMOBJ_CREATE:         return "SYS_MEMOBJ_CREATE";
        case SYS_MAP:                   return "SYS_MAP";
        case SYS_COPY_TO:               return "SYS_COPY_TO";
        case SYS_CAP_PORT_GRANT:        return "SYS_CAP_PORT_GRANT";
        case SYS_CAP_INITRAMFS:         return "SYS_CAP_INITRAMFS";
        case SYS_WAIT_FOR:              return "SYS_WAIT_FOR";
        case SYS_ENDPOINT_CREATE:       return "SYS_ENDPOINT_CREATE";
        case SYS_ENDPOINT_SEND:         return "SYS_ENDPOINT_SEND";
        case SYS_ENDPOINT_RECEIVE:      return "SYS_ENDPOINT_RECEIVE";
        case SYS_ENDPOINT_FREE_MESSAGE: return "SYS_ENDPOINT_FREE_MESSAGE";
        case SYS_HANDLE_DUP:            return "SYS_HANDLE_DUP";
        case SYS_HANDLE_CLOSE:          return "SYS_HANDLE_CLOSE";
        case SYS_HANDLE_GET_OWNER:      return "SYS_HANDLE_GET_OWNER";
        case SYS_MSG:                   return "SYS_MSG";
        case SYS_HANDLE_SET_OWNER:      return "SYS_HANDLE_SET_OWNER";
        case SYS_MEM_ALLOC:             return "SYS_MEM_ALLOC";
        case SYS_ENDPOINT_GET_OWNER:    return "SYS_ENDPOINT_GET_OWNER";
        case SYS_MEM_FREE:              return "SYS_MEM_FREE";
        case SYS_SET_FSBASE:            return "SYS_SET_FSBASE";
        default:                        return "UNKNOWN_SYSCALL";
    }
}

const char* convert_syscall_ret(syscall_ret_t ret) {
    if(ret.is_error == false) {
        return "SUCCESS";
    }
    switch(ret.err) {
        case SYSCALL_ERR_INVALID_ARGUMENT:  return "SYSCALL_ERR_INVALID_ARGUMENT";
        case SYSCALL_ERR_INVALID_SYSCALL:   return "SYSCALL_ERR_INVALID_SYSCALL";
        case SYSCALL_ERR_INVALID_HANDLE:    return "SYSCALL_ERR_INVALID_HANDLE";
        case SYSCALL_ERR_WOULD_BLOCK:       return "SYSCALL_ERR_WOULD_BLOCK";
        case SYSCALL_ERR_PERMISSION_DENIED: return "SYSCALL_ERR_PERMISSION_DENIED";
        case SYSCALL_ERR_OUT_OF_MEMORY:     return "SYSCALL_ERR_OUT_OF_MEMORY";
        case SYSCALL_ERR_ADDRESS_IN_USE:    return "SYSCALL_ERR_ADDRESS_IN_USE";
        case SYSCALL_ERR_INVALID_ADDRESS:   return "SYSCALL_ERR_INVALID_ADDRESS";
        case SYSCALL_ERR_INTERNAL_ERROR:    return "SYSCALL_ERR_INTERNAL_ERROR";
        default:                            return "UNKNOWN_SYSCALL_ERROR";
    }
}

syscall_ret_t syscall_sys_invalid(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void) arg1;
    (void) arg2;
    (void) arg3;
    (void) arg4;
    (void) arg5;
    (void) arg6;
    return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_SYSCALL);
}

// @note: syscall_nr is the LAST parameter so it's just *rsp
syscall_ret_t dispatch_syscall(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, syscall_nr_t syscall_nr) {
    thread_t* thread = CPU_LOCAL_READ(current_thread);
#if SYSTRACE_ENABLED == 0
    (void) thread;
#endif

    if(syscall_nr >= MAX_SYSCALL_NUMBER) {
#if SYSTRACE_ENABLED == 1
        printf(
            "[systrace] %d:%d - (0x%llx) %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = %s (0x%llx)\n",
            thread->thread_common.process->pid,
            thread->thread_common.tid,
            syscall_nr,
            convert_syscall_number(syscall_nr),
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6,
            convert_syscall_ret(SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_SYSCALL)),
            SYSCALL_ERR_INVALID_SYSCALL
        );
#endif
        return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_SYSCALL);
    }

    syscall_entry_t entry = syscall_table[syscall_nr];
    assert(entry.num_params <= 6 && "syscall entry has too many parameters");
#if SYSTRACE_ENABLED == 1
    char systrace_buf[1024];
    int index = snprintf(systrace_buf, 1024, "[systrace] %d:%d - (0x%llx) %s(", thread->thread_common.process->pid, thread->thread_common.tid, syscall_nr, convert_syscall_number(syscall_nr));
    switch(entry.num_params) {
        case 0:  index += snprintf(systrace_buf + index, 1024 - index, ")"); break;
        case 1:  index += snprintf(systrace_buf + index, 1024 - index, "0x%llx)", arg1); break;
        case 2:  index += snprintf(systrace_buf + index, 1024 - index, "0x%llx, 0x%llx)", arg1, arg2); break;
        case 3:  index += snprintf(systrace_buf + index, 1024 - index, "0x%llx, 0x%llx, 0x%llx)", arg1, arg2, arg3); break;
        case 4:  index += snprintf(systrace_buf + index, 1024 - index, "0x%llx, 0x%llx, 0x%llx, 0x%llx)", arg1, arg2, arg3, arg4); break;
        case 5:  index += snprintf(systrace_buf + index, 1024 - index, "0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)", arg1, arg2, arg3, arg4, arg5); break;
        case 6:  index += snprintf(systrace_buf + index, 1024 - index, "0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)", arg1, arg2, arg3, arg4, arg5, arg6); break;
        default: __builtin_unreachable();
    }

    printf("%s\n", systrace_buf);
#endif
    syscall_ret_t ret_value;

    switch(entry.num_params) {
        case 0:  ret_value = entry.handlers.handler0(); break;
        case 1:  ret_value = entry.handlers.handler1(arg1); break;
        case 2:  ret_value = entry.handlers.handler2(arg1, arg2); break;
        case 3:  ret_value = entry.handlers.handler3(arg1, arg2, arg3); break;
        case 4:  ret_value = entry.handlers.handler4(arg1, arg2, arg3, arg4); break;
        case 5:  ret_value = entry.handlers.handler5(arg1, arg2, arg3, arg4, arg5); break;
        case 6:  ret_value = entry.handlers.handler6(arg1, arg2, arg3, arg4, arg5, arg6); break;
        default: __builtin_unreachable();
    }

#if SYSTRACE_ENABLED == 1
    if(ret_value.is_error) {
        snprintf(systrace_buf + index, 1024 - index, " = %s (0x%lld)", convert_syscall_ret(ret_value), ret_value);
    } else {
        snprintf(systrace_buf + index, 1024 - index, " = SUCCESS (0x%llx)", ret_value.value);
    }
    printf("%s\n", systrace_buf);
#endif
    return ret_value;
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

    for(size_t i = 0; i < MAX_SYSCALL_NUMBER; i++) {
        syscall_table[i].num_params = 6;
        syscall_table[i].handlers.handler6 = syscall_sys_invalid;
    }

    SYSCALL_DISPATCHER(SYS_EXIT, syscall_sys_exit, 1);

    SYSCALL_DISPATCHER(SYS_PROCESS_CREATE_EMPTY, syscall_sys_process_create_empty, 0);
    SYSCALL_DISPATCHER(SYS_START, syscall_sys_start, 2);
    SYSCALL_DISPATCHER(SYS_MEMOBJ_CREATE, syscall_sys_memobj_create, 2);
    SYSCALL_DISPATCHER(SYS_MAP, syscall_sys_map, 5);
    SYSCALL_DISPATCHER(SYS_COPY_TO, syscall_sys_copy_to, 4);
    SYSCALL_DISPATCHER(SYS_PROCESS_THREAD_CREATE, syscall_sys_create_thread, 3);
    SYSCALL_DISPATCHER(SYS_PROCESS_GET_PID, syscall_sys_get_pid, 1);

    SYSCALL_DISPATCHER(SYS_CAP_PORT_GRANT, syscall_sys_cap_port_grant, 2);

    SYSCALL_DISPATCHER(SYS_CAP_INITRAMFS, syscall_sys_cap_initramfs, 0);

    SYSCALL_DISPATCHER(SYS_WAIT_FOR, syscall_sys_wait_for, 1);

    SYSCALL_DISPATCHER(SYS_ENDPOINT_CREATE, syscall_sys_endpoint_create, 0);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_SEND, syscall_sys_endpoint_send, 4);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_RECEIVE, syscall_sys_endpoint_receive, 1);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_FREE_MESSAGE, syscall_sys_endpoint_free_message, 1);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_GET_OWNER, syscall_sys_endpoint_get_owner, 1);

    SYSCALL_DISPATCHER(SYS_HANDLE_DUP, syscall_sys_handle_dup, 2);
    SYSCALL_DISPATCHER(SYS_HANDLE_CLOSE, syscall_sys_handle_close, 1);
    SYSCALL_DISPATCHER(SYS_HANDLE_GET_OWNER, syscall_sys_handle_get_owner, 1);
    SYSCALL_DISPATCHER(SYS_HANDLE_SET_OWNER, syscall_sys_handle_set_owner, 2);

    SYSCALL_DISPATCHER(SYS_MEM_ALLOC, syscall_sys_mem_alloc, 3);
    SYSCALL_DISPATCHER(SYS_MEM_FREE, syscall_sys_mem_free, 1);
    SYSCALL_DISPATCHER(SYS_MSG, syscall_sys_msg, 2);
    SYSCALL_DISPATCHER(SYS_SET_FSBASE, syscall_sys_set_fsbase, 1);
}
