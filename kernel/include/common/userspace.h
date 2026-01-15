#pragma once
#include <stdint.h>

typedef enum : uint64_t {
    SYS_EXIT = 1,

    SYS_PROCESS_CREATE_EMPTY = 16,
    SYS_START = 17,
    SYS_MEMOBJ_CREATE = 18,
    SYS_MAP = 19,
    SYS_COPY_TO = 20,

    SYS_CAP_PORT_GRANT = 32,
    
    // @todo: this absolutely 100% should not be a system call if we can help it
    SYS_CAP_IPC_DISCOVERY = 33,

    SYS_WAIT_FOR = 48,

    SYS_ENDPOINT_CREATE = 64,
    SYS_ENDPOINT_DESTROY = 65,
    SYS_ENDPOINT_SEND = 66,
    SYS_ENDPOINT_RECEIVE = 67,
    SYS_ENDPOINT_FREE_MESSAGE = 68
} syscall_nr_t;

typedef enum : int64_t {
    SYSCALL_ERR_INVALID_ARGUMENT = -1,
    SYSCALL_ERR_INVALID_SYSCALL = -2,
    SYSCALL_ERR_INVALID_HANDLE = -3,
    SYSCALL_ERR_WOULD_BLOCK = -4,
    SYSCALL_ERR_PERMISSION_DENIED = -5,
    SYSCALL_ERR_OUT_OF_MEMORY = -6,
    SYSCALL_ERR_ADDRESS_IN_USE = -7,
} syscall_err_t;

void userspace_init();

const char* convert_syscall_number(syscall_nr_t nr);
const char* convert_syscall_error(syscall_err_t err);
