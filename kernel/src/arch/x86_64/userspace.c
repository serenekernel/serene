#include <arch/cpu_local.h>
#include <arch/internal/gdt.h>
#include <arch/msr.h>
#include <assert.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
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

syscall_entry_t syscall_table[256];


const char* convert_syscall_number(syscall_nr_t nr) {
    switch(nr) {
        case SYS_EXIT:                  return "SYS_EXIT";
        case SYS_PROCESS_CREATE_EMPTY:  return "SYS_PROCESS_CREATE_EMPTY";
        case SYS_START:                 return "SYS_START";
        case SYS_MEMOBJ_CREATE:         return "SYS_MEMOBJ_CREATE";
        case SYS_MAP:                   return "SYS_MAP";
        case SYS_COPY_TO:               return "SYS_COPY_TO";
        case SYS_CAP_PORT_GRANT:        return "SYS_CAP_PORT_GRANT";
        case SYS_CAP_IPC_DISCOVERY:     return "SYS_CAP_IPC_DISCOVERY";
        case SYS_CAP_INITRAMFS:         return "SYS_CAP_INITRAMFS";
        case SYS_WAIT_FOR:              return "SYS_WAIT_FOR";
        case SYS_ENDPOINT_CREATE:       return "SYS_ENDPOINT_CREATE";
        case SYS_ENDPOINT_SEND:         return "SYS_ENDPOINT_SEND";
        case SYS_ENDPOINT_RECEIVE:      return "SYS_ENDPOINT_RECEIVE";
        case SYS_ENDPOINT_FREE_MESSAGE: return "SYS_ENDPOINT_FREE_MESSAGE";
        case SYS_HANDLE_DUP:            return "SYS_HANDLE_DUP";
        case SYS_HANDLE_CLOSE:          return "SYS_HANDLE_CLOSE";
        case SYS_HANDLE_GET_OWNER:      return "SYS_HANDLE_GET_OWNER";
        case SYS_HANDLE_SET_OWNER:      return "SYS_HANDLE_SET_OWNER";
        case SYS_MEM_ALLOC:             return "SYS_MEM_ALLOC";
        case SYS_MEM_FREE:              return "SYS_MEM_FREE";
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

    if(syscall_nr >= 256) {
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
        return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_SYSCALL);
    }

    syscall_entry_t entry = syscall_table[syscall_nr];
    assert(entry.num_params <= 6 && "syscall entry has too many parameters");

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

    snprintf(systrace_buf + index, 1024 - index, " = %s (0x%llx)", convert_syscall_ret(ret_value), ret_value);
    printf("%s\n", systrace_buf);

    return ret_value;
}

#define SYSCALL_DISPATCHER(nr, __handler, __num_params)           \
    syscall_table[nr].num_params = __num_params;                  \
    syscall_table[nr].handlers.handler##__num_params = __handler;

syscall_ret_t syscall_sys_exit(uint64_t exit_code);

syscall_ret_t syscall_sys_process_create_empty();
syscall_ret_t syscall_sys_start(uint64_t process_handle_value, uint64_t entry);
syscall_ret_t syscall_sys_memobj_create(uint64_t size, uint64_t perms);
syscall_ret_t syscall_sys_map(uint64_t process_handle_value, uint64_t memobj_handle_value, uint64_t vaddr, uint64_t perms, uint64_t flags);
syscall_ret_t syscall_sys_copy_to(uint64_t process_handle_value, uint64_t dst, uint64_t src, uint64_t size);

syscall_ret_t syscall_sys_cap_port_grant(uint64_t start_port, uint64_t num_ports);
syscall_ret_t syscall_sys_cap_ipc_discovery();
syscall_ret_t syscall_sys_cap_initramfs();

syscall_ret_t syscall_sys_wait_for(uint64_t handle_value);

syscall_ret_t syscall_sys_endpoint_create();
syscall_ret_t syscall_sys_endpoint_destroy(uint64_t handle_value);
syscall_ret_t syscall_sys_endpoint_send(uint64_t handle_value, uint64_t payload, uint64_t payload_length, uint64_t reply_handle_value);
syscall_ret_t syscall_sys_endpoint_receive(uint64_t handle_value);
syscall_ret_t syscall_sys_endpoint_free_message(uint64_t message_ptr);

syscall_ret_t syscall_sys_handle_dup(uint64_t handle_value);
syscall_ret_t syscall_sys_handle_close(uint64_t handle_value);
syscall_ret_t syscall_sys_handle_get_owner(uint64_t handle_value);
syscall_ret_t syscall_sys_handle_set_owner(uint64_t handle_value, uint64_t owner_pid_value);

syscall_ret_t syscall_sys_mem_alloc(uint64_t size, uint64_t align, uint64_t perms);
syscall_ret_t syscall_sys_mem_free(uint64_t addr);

void userspace_init() {
    uint64_t efer = __rdmsr(IA32_EFER);
    efer |= (1 << 0);
    __wrmsr(IA32_EFER, efer);

    uint64_t star = ((uint64_t) (0x18 | 3) << 48) | ((uint64_t) 0x08 << 32);
    __wrmsr(IA32_STAR, star);

    __wrmsr(IA32_LSTAR, (uint64_t) __handle_syscall);
    __wrmsr(IA32_SFMASK, ~0x2);

    for(size_t i = 0; i < 256; i++) {
        syscall_table[i].num_params = 6;
        syscall_table[i].handlers.handler6 = syscall_sys_invalid;
    }

    SYSCALL_DISPATCHER(SYS_EXIT, syscall_sys_exit, 1);

    SYSCALL_DISPATCHER(SYS_PROCESS_CREATE_EMPTY, syscall_sys_process_create_empty, 0);
    SYSCALL_DISPATCHER(SYS_START, syscall_sys_start, 2);
    SYSCALL_DISPATCHER(SYS_MEMOBJ_CREATE, syscall_sys_memobj_create, 2);
    SYSCALL_DISPATCHER(SYS_MAP, syscall_sys_map, 5);
    SYSCALL_DISPATCHER(SYS_COPY_TO, syscall_sys_copy_to, 4);

    SYSCALL_DISPATCHER(SYS_CAP_PORT_GRANT, syscall_sys_cap_port_grant, 2);

    SYSCALL_DISPATCHER(SYS_CAP_IPC_DISCOVERY, syscall_sys_cap_ipc_discovery, 0);
    SYSCALL_DISPATCHER(SYS_CAP_INITRAMFS, syscall_sys_cap_initramfs, 0);

    SYSCALL_DISPATCHER(SYS_WAIT_FOR, syscall_sys_wait_for, 1);

    SYSCALL_DISPATCHER(SYS_ENDPOINT_CREATE, syscall_sys_endpoint_create, 0);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_SEND, syscall_sys_endpoint_send, 4);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_RECEIVE, syscall_sys_endpoint_receive, 1);
    SYSCALL_DISPATCHER(SYS_ENDPOINT_FREE_MESSAGE, syscall_sys_endpoint_free_message, 1);

    SYSCALL_DISPATCHER(SYS_HANDLE_DUP, syscall_sys_handle_dup, 1);
    SYSCALL_DISPATCHER(SYS_HANDLE_CLOSE, syscall_sys_handle_close, 1);
    SYSCALL_DISPATCHER(SYS_HANDLE_GET_OWNER, syscall_sys_handle_get_owner, 1);
    SYSCALL_DISPATCHER(SYS_HANDLE_SET_OWNER, syscall_sys_handle_set_owner, 2);

    SYSCALL_DISPATCHER(SYS_MEM_ALLOC, syscall_sys_mem_alloc, 3);
    SYSCALL_DISPATCHER(SYS_MEM_FREE, syscall_sys_mem_free, 1);
}
