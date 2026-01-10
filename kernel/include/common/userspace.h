#pragma once
#include <stdint.h>

typedef enum : uint64_t {
    SYS_EXIT = 1,

    SYS_CAP_PORT_GRANT = 32,
} syscall_nr_t;

typedef enum : int64_t {
    SYSCALL_ERR_INVALID_ARGUMENT = -1,
    SYSCALL_INVALID_SYSCALL = -2,
} syscall_err_t;

void userspace_init();

const char* convert_syscall_number(syscall_nr_t nr);
const char* convert_syscall_error(syscall_err_t err);
